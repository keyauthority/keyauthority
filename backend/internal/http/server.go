/*
Copyright 2025 KeyAuthority.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package http

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"github.com/keyauthority/keyauthority/swagger"

	authpkg "github.com/keyauthority/keyauthority/internal/auth"
	cachepkg "github.com/keyauthority/keyauthority/internal/cache"
	cryptopkg "github.com/keyauthority/keyauthority/internal/crypto"
	databasepkg "github.com/keyauthority/keyauthority/internal/database"
	loggingpkg "github.com/keyauthority/keyauthority/internal/logging"
	metricspkg "github.com/keyauthority/keyauthority/internal/metrics"
	signerpkg "github.com/keyauthority/keyauthority/internal/signer"
)

const (
	envHTTPPort                 = "HTTP_PORT"
	envHTTPSPort                = "HTTPS_PORT"
	envMetricsPort              = "METRICS_PORT"
	envCORSOrigin               = "CORS_ORIGIN"
	envTruststore               = "TRUSTSTORE"
	envTLSCert                  = "TLS_CERT"
	envTLSKey                   = "TLS_KEY"
	envCRLRefreshInterval       = "CRL_REFRESH_INTERVAL"
	envStoreCleanupInterval     = "STORE_CLEANUP_INTERVAL"
	envInventoryRefreshInterval = "INVENTORY_REFRESH_INTERVAL"
)

type Server struct {
	Version  string
	Log      *loggingpkg.StdAndDBLogger
	DB       *databasepkg.Database
	ACME     *ACMEResponder
	Router   *mux.Router
	EnvCache *cachepkg.Cache // Cache prefix:name/id -> environment
}

func NewServer() *Server {
	return &Server{
		Version:  os.Getenv("VERSION"),
		Router:   mux.NewRouter(),
		EnvCache: cachepkg.NewCache(),
	}
}

func (server *Server) Start() {
	var err error

	// Ports
	httpPort := os.Getenv(envHTTPPort)
	httpsPort := os.Getenv(envHTTPSPort)
	metricsPort := os.Getenv(envMetricsPort)

	// TLS cert and key for HTTPS (optional)
	tlsCert := os.Getenv(envTLSCert)
	tlsKey := os.Getenv(envTLSKey)
	tlsEnabled := tlsCert != "" && tlsKey != ""

	// Create Database
	if server.DB, err = databasepkg.NewDatabase(context.Background()); err != nil {
		fmt.Printf("couldn't set up store: %v", err)
		return
	}
	defer server.DB.Close()

	// Create logger
	if server.Log, err = loggingpkg.NewLogger(context.Background(), server.DB.DB); err != nil {
		fmt.Printf("couldn't set up logger: %v", err)
		return
	}
	defer server.Log.Close()
	server.Log.InfoWithContext(context.Background(), "logger ready")

	// Set default HTTP transport
	server.setDefaultHttpTransport()

	// Set up the authenticator
	authpkg.SetupAuthenticator()
	server.Log.InfoWithContext(context.Background(), "authenticator ready")

	// Create ACME responder
	server.ACME = NewACMEResponder(server.DB, server.onCertificateSigned())
	server.Log.InfoWithContext(context.Background(), "ACME responder ready")

	// Metrics
	metricspkg.SetupMetrics()
	server.startMetricsServer(metricsPort)

	// Handlers
	// ---------- Keys ---------- //
	server.Router.Handle("/v1/keys", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet:  authpkg.RoleAny,      // get keys
			http.MethodPost: authpkg.RoleOperator, // create key
		},
		server.keysHandler()))

	server.Router.Handle("/v1/keys/{id}", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet:    authpkg.RoleOperator, // get key
			http.MethodDelete: authpkg.RoleOperator, // delete key
		},
		server.keyHandler()))

	server.Router.Handle("/v1/keys/{id}/ready", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleOperator, // get key readiness
		},
		server.keyReadinessHandler()))

	// ------------ Signers ------------ //
	server.Router.Handle("/v1/signers", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleAny, // get signers
		},
		server.signersHandler()))

	server.Router.Handle("/v1/signers/{name}", server.withAuth(
		map[string]authpkg.Role{
			http.MethodPost:   authpkg.RoleOperator, // create signer
			http.MethodDelete: authpkg.RoleOperator, // delete signer
		},
		server.signerHandler()))

	server.Router.Handle("/v1/signers/{name}/private-key", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleOperator, // get private key ID
		},
		server.signerPrivateKeyHandler()))

	server.Router.Handle("/v1/signers/{name}/config", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleOperator, // get signer config
			http.MethodPut: authpkg.RoleOperator, // update signer config
		},
		server.signerConfigHandler()))

	server.Router.Handle("/v1/signers/{name}/ca-chain", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleOperator, // get CA chain
			http.MethodPut: authpkg.RoleOperator, // update CA chain
		},
		server.signerCAChainHandler()))

	server.Router.Handle("/v1/signers/{name}/ca-csr", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleOperator, // create CA CSR
		},
		server.signerCSRHandler()))

	server.Router.Handle("/v1/signers/{name}/sign",
		metricspkg.WithHttpMetrics("/v1/signers/{name}/sign", server.withAuth(
			map[string]authpkg.Role{
				http.MethodPost: authpkg.RoleOperator, // sign certificate
			},
			server.signerSignHandler())))

	server.Router.Handle("/v1/signers/{name}/revoke",
		metricspkg.WithHttpMetrics("/v1/signers/{name}/revoke", server.withAuth(
			map[string]authpkg.Role{
				http.MethodPost: authpkg.RoleOperator, // revoke certificate
			},
			server.signerRevokeHandler())))

	server.Router.PathPrefix("/v1/signers/{name}/acme").Handler(
		server.signerACMEHandler())

	// CRL is registered on the main router only when TLS is disabled.
	// When TLS is enabled, it gets its own plain HTTP listener (see bottom of main).
	if !tlsEnabled {
		server.Router.Handle("/v1/crl/{hashOfSignerName:.*}", server.signerCRLHandler())
		server.Router.Handle("/v1/aia/{hashOfSignerName:.*}", server.signerAIAHandler())
	}

	// ------------ Secrets ------------ //
	server.Router.Handle("/v1/secrets", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleAny, // get secrets
		},
		server.secretsHandler()))

	server.Router.Handle("/v1/secrets/data/{name:.+}",
		metricspkg.WithHttpMetrics("/v1/secrets/data/{name}", server.withAuth(
			map[string]authpkg.Role{
				http.MethodGet: authpkg.RoleOperator, // get secret (Hashicorp Vault compatible)
			},
			server.secretHandler())))

	server.Router.Handle("/v1/secrets/{name:.+}",
		metricspkg.WithHttpMetrics("/v1/secrets/{name}", server.withAuth(
			map[string]authpkg.Role{
				http.MethodGet:    authpkg.RoleOperator, // get secret
				http.MethodPut:    authpkg.RoleOperator, // insert secret
				http.MethodPost:   authpkg.RoleOperator, // update secret
				http.MethodPatch:  authpkg.RoleOperator, // patch secret
				http.MethodDelete: authpkg.RoleOperator, // delete secret
			},
			server.secretHandler())))

	// ---------- Certificates ---------- //
	server.Router.Handle("/v1/certs", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleAny, // get certs
		},
		server.certsHandler()))

	server.Router.Handle("/v1/certs/{serial}/pem", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleAny, // get cert PEM
		},
		server.certHandler()))

	// ------------ Pending Requests ------------ //
	server.Router.Handle("/v1/pending-requests", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleApprover, // get pending requests
		},
		server.pendingRequestsHandler()))

	server.Router.Handle("/v1/pending-requests/{id}",
		metricspkg.WithHttpMetrics("/v1/pending-requests/{id}", server.withAuth(
			map[string]authpkg.Role{
				http.MethodPost:   authpkg.RoleApprover, // approve pending request
				http.MethodDelete: authpkg.RoleApprover, // reject pending request
			},
			server.pendingRequestHandler())))

	server.Router.Handle("/v1/pending-requests/{id}/body", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleApprover, // get pending request body
		},
		server.pendingRequestBodyHandler()))

	// ------------ Miscellaneous ------------ //
	server.Router.Handle("/v1/dashboard", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleAny,
		},
		server.dashboardHandler()))

	server.Router.Handle("/v1/logs", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleAuditor, // get logs
		},
		server.logsHandler()))

	server.Router.Handle("/v1/token", server.tokenHandler())

	server.Router.Handle("/v1/health", server.healthHandler())

	server.Router.Handle("/v1/oidc/jwks/kubernetes", server.kubernetesJWKSHandler())

	// ----- Other Hashicorp Vault compatible paths ----- //
	server.Router.Handle("/v1/auth/{mount}/login", server.tokenHandler())

	server.Router.Handle("/v1/sys/health", server.healthHandler())

	server.Router.PathPrefix("/v1/sys/internal/ui/mounts/").Handler(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSONOk(w, map[string]any{
				"type": "kv",
				"path": "secrets/",
				"options": map[string]any{
					"version": "2",
				},
			})
		}))

	// ------------ Swagger ------------ //
	server.Router.PathPrefix("/swagger/").Handler(
		http.StripPrefix("/swagger/", http.FileServer(http.FS(swagger.Files))))

	// ------------ Periodic Tasks ----- //
	server.runPeriodicTasks()

	// ------------ Start server ------------ //
	server.Log.InfoWithContext(context.Background(), "server started", "version", server.Version)

	if tlsEnabled {
		server.Log.InfoWithContext(context.Background(), "TLS enabled")

		// CRL and AIA must always be served over plain HTTP
		nonTLSRouter := mux.NewRouter()
		nonTLSRouter.Handle("/v1/crl/{hashOfSignerName:.*}", server.signerCRLHandler())
		nonTLSRouter.Handle("/v1/aia/{hashOfSignerName:.*}", server.signerAIAHandler())
		go func() {
			server.Log.InfoWithContext(context.Background(), "non-TLS server (CRL, AIA) started")
			if err := http.ListenAndServe(":"+httpPort, nonTLSRouter); err != nil {
				server.Log.ErrorWithContext(context.Background(), "non-TLS server (CRL, AIA) stopped", "error", err)
			}
		}()

		http.ListenAndServeTLS(":"+httpsPort, tlsCert, tlsKey,
			server.withSecurityHeaders(server.withCORS(server.Router)))
	} else {
		http.ListenAndServe(":"+httpPort,
			server.withSecurityHeaders(server.withCORS(server.Router)))
	}
}

func (server *Server) startMetricsServer(metricsPort string) {
	if metricsPort == "" {
		server.Log.WarnWithContext(context.Background(),
			"metrics server disabled: METRICS_PORT is not set")
		return
	}

	metricsRouter := mux.NewRouter()
	metricsRouter.Handle("/metrics", metricspkg.MetricsHandler())

	go func() {
		server.Log.InfoWithContext(context.Background(), "metrics server started")

		if err := http.ListenAndServe(":"+metricsPort, metricsRouter); err != nil {
			server.Log.ErrorWithContext(context.Background(),
				"metrics server stopped", "error", err)
		}
	}()
}

func (server *Server) runPeriodicTasks() {
	// CRL recreation
	go func() {
		intervalStr := os.Getenv(envCRLRefreshInterval)
		if intervalStr == "" {
			intervalStr = "72h"
		}
		crlRecreationInterval, err := time.ParseDuration(intervalStr)
		if err != nil {
			server.Log.WarnWithContext(context.Background(),
				"invalid CRL refresh interval, using default of 72h",
				"error", err, "intervalStr", intervalStr)
			crlRecreationInterval = 72 * time.Hour
		}

		ticker := time.NewTicker(crlRecreationInterval)
		defer ticker.Stop()

		for {
			successCount, failureCount, err := server.recreateCRLs()
			if err != nil {
				server.Log.WarnWithContext(context.Background(), "couldn't recreate CRLs", "error", err)
			} else {
				server.Log.DebugWithContext(context.Background(), "CRL recreation completed",
					"succeeded", successCount, "failed", failureCount)
			}
			<-ticker.C
		}
	}()

	// Store Cleanup
	go func() {
		intervalStr := os.Getenv(envStoreCleanupInterval)
		if intervalStr == "" {
			intervalStr = "24h"
		}
		storeCleanupInterval, err := time.ParseDuration(intervalStr)
		if err != nil {
			server.Log.WarnWithContext(context.Background(),
				"invalid store cleanup interval, using default of 24h",
				"error", err, "intervalStr", intervalStr)
			storeCleanupInterval = 24 * time.Hour
		}

		time.Sleep(storeCleanupInterval) // initial delay before first cleanup
		ticker := time.NewTicker(storeCleanupInterval)
		defer ticker.Stop()

		for {
			if err := server.DB.RunCleanupTasks(context.Background()); err != nil {
				server.Log.WarnWithContext(context.Background(),
					"couldn't perform store cleanup tasks", "error", err)
			} else {
				server.Log.DebugWithContext(context.Background(),
					"store cleanup tasks completed")
			}
			<-ticker.C
		}
	}()

	// Store Inventory Refresh
	go func() {
		intervalStr := os.Getenv(envInventoryRefreshInterval)
		if intervalStr == "" {
			intervalStr = "30m"
		}
		inventoryRefreshInterval, err := time.ParseDuration(intervalStr)
		if err != nil {
			server.Log.WarnWithContext(context.Background(),
				"invalid inventory refresh interval, using default of 30m",
				"error", err, "intervalStr", intervalStr)
			inventoryRefreshInterval = 30 * time.Minute
		}

		ticker := time.NewTicker(inventoryRefreshInterval)
		defer ticker.Stop()

		for {
			if err := server.DB.RefreshInventoryMetrics(context.Background()); err != nil {
				server.Log.WarnWithContext(context.Background(),
					"couldn't refresh inventory metrics", "error", err)
			} else {
				server.Log.DebugWithContext(context.Background(),
					"inventory metrics refreshed")
			}
			<-ticker.C
		}
	}()
}

func (server *Server) recreateCRLs() (int, int, error) {
	ctx := context.Background()
	signers, err := server.DB.GetAllSigners(ctx)
	if err != nil {
		return 0, 0, err
	}

	successCount := 0
	for _, signerName := range signers {
		signer, err := server.DB.LoadSigner(ctx, signerName)
		if err != nil {
			server.Log.WarnWithContext(ctx, "couldn't load signer", "signer", signerName, "error", err)
			continue
		}

		existingCRL, err := server.DB.GetSignerCRL(ctx, signerName)
		if err != nil {
			server.Log.WarnWithContext(ctx, "couldn't get existing CRL", "signer", signerName, "error", err)
			continue
		}

		crl, err := signer.SignCRL(existingCRL, nil)
		if err != nil {
			server.Log.WarnWithContext(ctx, "couldn't create CRL", "signer", signerName, "error", err)
			continue
		}

		if err := server.DB.SetSignerCRL(ctx, signerName, crl); err != nil {
			server.Log.WarnWithContext(ctx, "couldn't store CRL", "signer", signerName, "error", err)
			continue
		}

		server.Log.InfoWithContext(ctx, "CRL updated", "signer", signerName)
		successCount++
	}
	return successCount, len(signers) - successCount, nil
}

func (server *Server) setDefaultHttpTransport() {
	caPool, err := x509.SystemCertPool()
	if err != nil {
		server.Log.ErrorWithContext(context.Background(), "couldn't load system cert pool",
			"error", err)
		return
	}

	// Load extra CA certificates from file paths
	paths := os.Getenv(envTruststore)
	if paths != "" {
		paths := strings.SplitSeq(paths, ",")
		for path := range paths {
			caCert, err := os.ReadFile(strings.TrimSpace(path))
			if err != nil {
				server.Log.WarnWithContext(context.Background(), "couldn't load CA from file",
					"path", path, "error", err)
				continue
			}
			if ok := caPool.AppendCertsFromPEM(caCert); !ok {
				server.Log.WarnWithContext(context.Background(), "couldn't append CA from file",
					"path", path)
			}
		}
	}

	defaultTransport := http.DefaultTransport.(*http.Transport)
	if defaultTransport.TLSClientConfig == nil {
		defaultTransport.TLSClientConfig = &tls.Config{}
	}
	defaultTransport.TLSClientConfig.RootCAs = caPool
	defaultTransport.TLSClientConfig.InsecureSkipVerify = false
	defaultTransport.TLSClientConfig.MinVersion = tls.VersionTLS12
}

func (server *Server) logErrorAndWriteHTTP(w http.ResponseWriter, r *http.Request, code int, msg string, args ...any) {
	var errors []error
	var logArgs []any
	for i := range args {
		if e, isError := args[i].(error); isError && e != nil {
			logArgs = append(logArgs, "error", e)
			errors = append(errors, e)
		}
	}

	server.Log.Error(r, msg, logArgs...)

	var m struct {
		Errors []string `json:"errors"`
	}
	m.Errors = []string{msg}

	// Exclude 500+ errors
	if code < http.StatusInternalServerError {
		for _, err := range errors {
			m.Errors = append(m.Errors, err.Error())
		}
	}

	b, _ := json.Marshal(m)

	writeHTTPWithHeaders(w, code, b,
		map[string]string{"Content-Type": "application/json"})
}

// Hook called when a certificate is signed
func (server *Server) onCertificateSigned() func(r *http.Request, cert *x509.Certificate, comment string) {
	return func(r *http.Request, cert *x509.Certificate, comment string) {
		signerName := mux.Vars(r)["name"]
		server.Log.Info(r, "certificate signed",
			slog.String("serial", signerpkg.BigIntToString(cert.SerialNumber)),
			slog.String("signerName", signerName),
			slog.String("cn", cert.Subject.CommonName),
			slog.Any("dns", cert.DNSNames),
			slog.Any("notBefore", cert.NotBefore),
			slog.Any("notAfter", cert.NotAfter),
			slog.String("comment", comment),
		)

		// Insert cert in DB asynchronously, to avoid delaying the response to the client
		go func() {
			err := server.DB.InsertCert(context.Background(), signerName, cert, comment)
			if err != nil {
				server.Log.Error(r, "couldn't insert certificate", "error", err)
			}
		}()
	}
}

func (server *Server) getPaginatedListWithCursor(
	r *http.Request,
	w http.ResponseWriter,
	getFunc func(ctx context.Context, filters url.Values) (*databasepkg.CursorPaginationResult, error),
) {
	filters := r.URL.Query()

	result, err := getFunc(r.Context(), filters)
	if err != nil {
		server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't get items", err)
		return
	}

	writeJSONOk(w, result)
}

func (server *Server) getPaginatedListWithAccessibleEnvsAndCursor(
	r *http.Request,
	w http.ResponseWriter,
	getFunc func(ctx context.Context, hasAccessToAllEnvs bool, accessibleEnvs []string, filters url.Values) (*databasepkg.CursorPaginationResult, error),
) {
	hasAccessToAllEnvs, accessibleEnvs, err := getAccessibleEnvs(r.Context())
	if err != nil {
		server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't get accessible environments", err)
		return
	}

	filters := r.URL.Query()

	result, err := getFunc(r.Context(), hasAccessToAllEnvs, accessibleEnvs, filters)
	if err != nil {
		server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't get items", err)
		return
	}

	writeJSONOk(w, result)
}

func (server *Server) requiresApproval(r *http.Request) bool {
	// already approved, no need for approval again
	if _, ok := r.Context().Value(loggingpkg.CtxKeyOriginalRequestID{}).(uuid.UUID); ok {
		return false
	}

	if isUpdateSignerRequest(r) || isSigningRequest(r) {
		cfg, err := server.DB.GetSignerConfig(r.Context(), mux.Vars(r)["name"])
		if err != nil {
			return false
		}
		return cfg.ApprovalRequired
	}

	return false
}

func (server *Server) getEnvironment(r *http.Request) (string, error) {
	ctx := r.Context()

	// signer requests
	if strings.HasPrefix(r.URL.Path, "/v1/signers/") {
		signerName := mux.Vars(r)["name"]
		cacheKey := "signer:" + signerName
		if env, ok := server.EnvCache.Get(cacheKey); ok {
			server.Log.Debug(r, "environment cache hit", "environment", env)
			return env.(string), nil
		}

		// on create signer, derive from privateKeyID query param
		if isCreateSignerRequest(r) {
			keyID := r.URL.Query().Get("privateKeyID")
			return server.DB.GetKeyEnvironment(ctx, keyID)
		}

		env, err := server.DB.GetSignerEnvironment(ctx, signerName)
		if err != nil {
			return "", err
		}

		server.EnvCache.Set(cacheKey, env)
		return env, nil
	}

	// secret requests
	if strings.HasPrefix(r.URL.Path, "/v1/secrets/") {
		secretName := mux.Vars(r)["name"]
		cacheKey := "secret:" + secretName
		if env, ok := server.EnvCache.Get(cacheKey); ok {
			server.Log.Debug(r, "environment cache hit", "environment", env)
			return env.(string), nil
		}

		// on insert secret, derive from encryptionKeyID query param
		if isInsertSecretRequest(r) {
			keyID := r.URL.Query().Get("encryptionKeyID")
			return server.DB.GetKeyEnvironment(ctx, keyID)
		}

		env, err := server.DB.GetSecretEnvironment(ctx, secretName)
		if err != nil {
			return "", err
		}
		server.EnvCache.Set(cacheKey, env)
		return env, nil
	}

	// key requests
	if strings.HasPrefix(r.URL.Path, "/v1/keys/") || isCreateKeyRequest(r) {
		// on create key, derive from environment query param
		if isCreateKeyRequest(r) {
			env := r.URL.Query().Get("environment")
			if env == "" {
				return "", fmt.Errorf("missing environment query parameter")
			}
			return env, nil
		}

		keyID := mux.Vars(r)["id"]
		cacheKey := "key:" + keyID
		if env, ok := server.EnvCache.Get(cacheKey); ok {
			server.Log.Debug(r, "environment cache hit", "environment", env)
			return env.(string), nil
		}

		env, err := server.DB.GetKeyEnvironment(ctx, keyID)
		if err != nil {
			return "", fmt.Errorf("couldn't get key environment: %w", err)
		}

		server.EnvCache.Set(cacheKey, env)
		return env, nil
	}

	return "", nil
}

/******************************/
/*        Keys handlers       */
/******************************/
func (server *Server) keysHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet: // get keys
			server.getPaginatedListWithAccessibleEnvsAndCursor(r, w, server.DB.GetKeysWithCursor)

		case http.MethodPost: // create key
			q := r.URL.Query()
			environment := q.Get("environment")
			if environment == "" {
				server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "environment query parameter is required")
				return
			}
			var cfg cryptopkg.KeyConfig
			if err := decodeJSONBody(r, &cfg); err != nil {
				server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't decode body", err)
				return
			}

			if cfg.PKCS11Uri != "" {
				// it's an HSM key
				if cfg.PKCS11KeyUri == "" {
					// If this is an HSM key and no key URI is defined, create one with a random ID
					hsmKeyID := make([]byte, 16)
					if _, err := rand.Read(hsmKeyID); err != nil {
						server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError,
							"couldn't create random ID for HSM key URI", err)
						return
					}
					cfg.PKCS11KeyUri = fmt.Sprintf("pkcs11:id=%s;object=keyauthority",
						hex.EncodeToString(hsmKeyID))
				}
			}

			tokenInfo, ok := r.Context().Value(loggingpkg.CtxKeyTokenInfo{}).(*loggingpkg.TokenInfo)
			if !ok || tokenInfo == nil {
				server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't get token info from context")
				return
			}
			user := tokenInfo.GetHumanReadableUsername()

			keyID, err := server.DB.CreateKey(r.Context(), environment, &cfg, user)
			if err != nil {
				server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't create key", err)
				return
			}

			server.Log.Info(r, "key created",
				"keyID", keyID,
				"environment", environment,
				"config", cfg)

			writeHTTPWithHeaders(w, http.StatusCreated, []byte(keyID.String()),
				map[string]string{
					"Content-Type": "text/plain",
				})
		}
	})
}

func (server *Server) keyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keyIDStr := mux.Vars(r)["id"]
		keyID, err := uuid.Parse(keyIDStr)
		if err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "invalid key ID", err)
			return
		}

		switch r.Method {
		case http.MethodGet:
			key, err := server.DB.GetKey(r.Context(), keyID)
			if err != nil {
				server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't get key", err)
				return
			}
			writeJSONOk(w, key)

		case http.MethodDelete:
			if err := server.DB.DeleteKey(r.Context(), keyID); err != nil {
				server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't delete key", err)
				return
			}
			server.EnvCache.Delete("key:" + keyIDStr) // invalidate environment cache for this key
			server.Log.Info(r, "key deleted if existed")
			writeJSONOk(w, nil)
		}
	})
}

func (server *Server) keyReadinessHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keyIDStr := mux.Vars(r)["id"]
		keyID, err := uuid.Parse(keyIDStr)
		if err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "invalid key ID", err)
			return
		}

		if err := server.DB.CheckKeyReadiness(r.Context(), keyID); err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "key is not ready", err)
			return
		}

		server.Log.Debug(r, "key is ready")
		writeHTTP(w, http.StatusOK, nil)
	})
}

/******************************/
/*    Certificates handlers   */
/******************************/
func (server *Server) certHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serial := mux.Vars(r)["serial"]
		pem, err := server.DB.GetCertPEM(r.Context(), serial)
		if err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't get certificate", err)
			return
		}
		writeHTTPWithHeaders(w, http.StatusOK, pem,
			map[string]string{
				"Content-Type":        "application/x-pem-file",
				"Content-Disposition": fmt.Sprintf(`attachment; filename="%s.pem"`, serial),
			})
	})
}

func (server *Server) certsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server.getPaginatedListWithAccessibleEnvsAndCursor(r, w, server.DB.GetCertsWithCursor)
	})
}

/******************************/
/*      Signers handlers      */
/******************************/
func (server *Server) signersHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server.getPaginatedListWithAccessibleEnvsAndCursor(r, w, server.DB.GetSignersWithCursor)
	})
}

func (server *Server) signerHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signerName := mux.Vars(r)["name"]

		switch r.Method {
		case http.MethodPost: // create signer
			q := r.URL.Query()
			privateKeyID := q.Get("privateKeyID")
			if privateKeyID == "" {
				server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "privateKeyID query parameter is required", nil)
				return
			}

			keyID, err := uuid.Parse(privateKeyID)
			if err != nil {
				server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't parse key ID", err)
				return
			}
			if _, err := server.DB.LoadKey(r.Context(), keyID); err != nil {
				server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't load private key", err)
				return
			}

			var cfg signerpkg.SignerConfig
			if err := decodeJSONBody(r, &cfg); err != nil {
				server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't decode body", err)
				return
			}

			if err := server.DB.CreateSigner(r.Context(), signerName, keyID, &cfg); err != nil {
				server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't create signer", err)
				return
			}

			server.Log.Info(r, "signer created", "keyID", keyID, "config", cfg)
			writeHTTP(w, http.StatusCreated, nil)

		case http.MethodDelete: // delete signer
			if err := server.DB.DeleteSigner(r.Context(), signerName); err != nil {
				server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't delete signer", err)
				return
			}
			server.EnvCache.Delete("signer:" + signerName) // invalidate environment cache for this signer
			server.Log.Info(r, "signer deleted")
			writeJSONOk(w, nil)
		}
	})
}

func (server *Server) signerPrivateKeyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signerName := mux.Vars(r)["name"]
		privateKeyID, err := server.DB.GetPrivateKeyID(r.Context(), signerName)
		if err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't get signer private key ID", err)
			return
		}
		writeHTTPWithHeaders(w, http.StatusOK, []byte(privateKeyID.String()),
			map[string]string{
				"Content-Type": "text/plain",
			})
	})
}

func (server *Server) signerConfigHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signerName := mux.Vars(r)["name"]
		switch r.Method {
		case http.MethodGet: // get signer config
			cfg, err := server.DB.GetSignerConfig(r.Context(), signerName)
			if err != nil {
				server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't get signer config", err)
				return
			}
			writeJSONOk(w, cfg)

		case http.MethodPut: // update signer config
			var cfg signerpkg.SignerConfig
			if err := decodeJSONBody(r, &cfg); err != nil {
				server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't decode body", err)
				return
			}

			if err := server.DB.SetSignerConfig(r.Context(), signerName, &cfg); err != nil {
				server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't update signer config", err)
				return
			}

			server.Log.Info(r, "signer config updated", "config", cfg)
			writeJSONOk(w, nil)
		}

	})
}

func (server *Server) signerCAChainHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signerName := mux.Vars(r)["name"]
		switch r.Method {
		case http.MethodGet: // get CA chain
			caChain, err := server.DB.GetSignerCAChain(r.Context(), signerName)
			if err != nil {
				server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't get signer CA chain", err)
				return
			}

			writeHTTPWithHeaders(w, http.StatusOK, caChain, map[string]string{
				"Content-Type":        "application/x-pem-file",
				"Content-Disposition": "attachment; filename=ca-chain.pem",
			})

		case http.MethodPut: // update CA chain
			signer, err := server.DB.LoadSigner(r.Context(), signerName)
			if err != nil {
				server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't load signer", err)
				return
			}

			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't read body", err)
				return
			}
			if err := signer.SetCAChain(bodyBytes); err != nil {
				server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't assign CA chain to signer", err)
				return
			}
			if err := server.DB.SetSignerCAChain(r.Context(), signerName, bodyBytes); err != nil {
				server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't save CA chain", err)
				return
			}
			server.Log.Info(r, "CA chain updated")
			writeJSONOk(w, nil)
		}
	})
}

func (server *Server) signerCSRHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signerName := mux.Vars(r)["name"]
		signer, err := server.DB.LoadSigner(r.Context(), signerName, signerpkg.IgnoreCAChainErrors(true))
		if err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't load signer", err)
			return
		}

		csr, err := signer.CreateCSR()
		if err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't create CA CSR", err)
			return
		}

		server.Log.Info(r, "CA CSR created")
		writeHTTPWithHeaders(w, http.StatusOK, csr, map[string]string{
			"Content-Type":        "application/x-pem-file",
			"Content-Disposition": "attachment; filename=ca-csr.pem",
		})
	})
}

func (server *Server) signerSignHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signerName := mux.Vars(r)["name"]
		signer, err := server.DB.LoadSigner(r.Context(), signerName)
		if err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't load signer", err)
			return
		}

		type Body struct {
			CSR     string `json:"csr"`
			TTL     string `json:"ttl"`
			Comment string `json:"comment,omitempty"`
		}
		var body Body
		if err := decodeJSONBody(r, &body); err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't decode body", err)
			return
		}

		cr, err := signerpkg.ParseCSR([]byte(body.CSR))
		if err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't parse CSR", err)
			return
		}

		ttl, err := time.ParseDuration(body.TTL)
		if err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't parse TTL", err)
			return
		}

		cert, fullChain, err := signer.Sign(cr, ttl)
		if err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't sign certificate", err)
			return
		}

		server.onCertificateSigned()(r, cert, body.Comment)

		type Data struct {
			Certificate string   `json:"certificate"`
			IssuingCA   string   `json:"issuing_ca,omitempty"`
			CAChain     []string `json:"ca_chain,omitempty"`
		}
		type Resp struct {
			Data *Data `json:"data"`
		}
		resp := Resp{
			Data: &Data{
				Certificate: fullChain[0],
			},
		}
		if len(fullChain) > 1 {
			resp.Data.IssuingCA = fullChain[1]
			resp.Data.CAChain = fullChain[1:]

		}
		writeJSONOk(w, resp)
	})
}

func (server *Server) signerCRLHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hash := mux.Vars(r)["hashOfSignerName"]
		crl, err := server.DB.GetSignerCRLByHash(r.Context(), hash)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				server.logErrorAndWriteHTTP(w, r, http.StatusNotFound, "CRL not found for signer", err)
			} else {
				server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't get CRL for signer", err)
			}
			return
		}
		writeHTTPWithHeaders(w, http.StatusOK, crl,
			map[string]string{
				"Content-Type":                "application/pkix-crl",
				"Cache-Control":               "public, max-age=3600", // 1 hour cache
				"X-Content-Type-Options":      "nosniff",
				"Access-Control-Allow-Origin": "*", // Allow all origins
				"Content-Disposition":         `attachment; filename="crl.crl"`,
			})
	})
}

func (server *Server) signerAIAHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hash := mux.Vars(r)["hashOfSignerName"]
		caCert, err := server.DB.GetSignerCACertByHash(r.Context(), hash)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				server.logErrorAndWriteHTTP(w, r, http.StatusNotFound, "CA certificate not found for signer", err)
			} else {
				server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't get CA certificate for signer", err)
			}
			return
		}
		writeHTTPWithHeaders(w, http.StatusOK, caCert,
			map[string]string{
				"Content-Type":                "application/x-pem-file",
				"Cache-Control":               "public, max-age=3600", // 1 hour cache
				"X-Content-Type-Options":      "nosniff",
				"Access-Control-Allow-Origin": "*", // Allow all origins
				"Content-Disposition":         `attachment; filename="ca.pem"`,
			})
	})
}

func (server *Server) signerRevokeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signerName := mux.Vars(r)["name"]
		signer, err := server.DB.LoadSigner(r.Context(), signerName)
		if err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't load signer", err)
			return
		}

		var revocationPair signerpkg.RevocationPair
		if err := decodeJSONBody(r, &revocationPair); err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't decode body", err)
			return
		}

		existingCRL, err := server.DB.GetSignerCRL(r.Context(), signerName)
		if err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't get existing CRL", err)
			return
		}

		crl, err := signer.SignCRL(existingCRL, []signerpkg.RevocationPair{revocationPair})
		if err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't sign CRL", err)
			return
		}

		if err := server.DB.SetSignerCRL(r.Context(), signerName, crl); err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't save new CRL", err)
			return
		}

		if err := server.DB.SetCertAsRevoked(r.Context(), revocationPair.Serial); err != nil {
			server.Log.Warn(r, "couldn't set certificate as revoked", "error", err)
		}

		server.Log.Info(r, "certificate revoked",
			"serial", revocationPair.Serial, "reason", revocationPair.Reason)
		writeJSONOk(w, nil)
	})
}

func (server *Server) signerACMEHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// for ACME finalize requests, we need to determine the environment for logging context
		if strings.HasSuffix(r.URL.Path, "/acme/finalize") {
			environment, err := server.getEnvironment(r)
			if err != nil {
				server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't determine environment", err)
				return
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, loggingpkg.CtxKeyEnvironment{}, environment)
			ctx = context.WithValue(ctx, loggingpkg.CtxKeyWriteLogToDB{}, true)
			r = r.WithContext(ctx)
		}

		resp, code, headers, err := server.ACME.BuildResponse(r)
		if err != nil {
			server.logErrorAndWriteHTTP(w, r, code, "couldn't handle ACME request", err)
			return
		}
		if code == http.StatusCreated && strings.HasSuffix(r.URL.Path, "/new-acct") {
			server.Log.Info(r, "ACME account created", "uri", headers["Location"])
		}

		server.Log.Debug(r, "ACME request handled", "code", code)
		writeHTTPWithHeaders(w, code, resp, headers)
	})
}

/******************************/
/*      Secrets handlers      */
/******************************/
func (server *Server) secretsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server.getPaginatedListWithAccessibleEnvsAndCursor(r, w, server.DB.GetSecretsWithCursor)
	})
}

func (server *Server) secretHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secretName := mux.Vars(r)["name"]

		switch r.Method {
		case http.MethodGet: // get secret
			secret, err := server.DB.GetSecret(r.Context(), secretName)
			if err != nil {
				server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't get secret", err)
				return
			}
			server.Log.Info(r, "secret read")

			switch r.URL.Query().Get("output") {
			case "shell":
				var shell strings.Builder
				data, ok := secret["data"].(map[string]string)
				if !ok {
					server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "invalid secret data type", nil)
					return
				}
				for k, v := range data {
					shell.WriteString(fmt.Sprintf(`export %s='%s'`, k, v) + "\n")
				}
				writeHTTP(w, http.StatusOK, []byte(shell.String()))

			default:
				// for Hashicorp-style response, we need to add an extra 'data' layer in the response
				if r.URL.Path == "/v1/secrets/data/"+secretName {
					writeJSONOk(w, map[string]any{
						"data": secret,
					})
					return
				}
				writeJSONOk(w, secret)
			}

		case http.MethodPut: // insert secret
			encryptionKeyIDStr := r.URL.Query().Get("encryptionKeyID")
			if encryptionKeyIDStr == "" {
				server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "encryptionKeyID query parameter is required for secret creation", nil)
				return
			}
			encryptionKeyID, err := uuid.Parse(encryptionKeyIDStr)
			if err != nil {
				server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "invalid encryption key ID", err)
				return
			}

			var data map[string]string
			if err := decodeJSONBody(r, &data); err != nil {
				server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't decode body", err)
				return
			}

			if err := server.DB.InsertSecret(r.Context(), secretName, encryptionKeyID, data); err != nil {
				server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't insert secret", err)
				return
			}
			server.Log.Info(r, "secret inserted", "encryptionKeyID", encryptionKeyID)
			writeHTTP(w, http.StatusCreated, nil)

		case http.MethodPost, http.MethodPatch: // update/patch secret
			var data map[string]string
			if err := decodeJSONBody(r, &data); err != nil {
				server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't decode body", err)
				return
			}

			err := server.DB.UpdateSecret(r.Context(), secretName, data, r.Method == http.MethodPatch)
			if err != nil {
				server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't update secret", err)
				return
			}
			server.Log.Info(r, "secret updated/patched")
			writeJSONOk(w, nil)

		case http.MethodDelete:
			if err := server.DB.DeleteSecret(r.Context(), secretName); err != nil {
				server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError,
					"couldn't delete secret", err)
				return
			}
			server.EnvCache.Delete("secret:" + secretName) // invalidate environment cache for this secret
			server.Log.Info(r, "secret deleted if existed")
			writeJSONOk(w, nil)
		}
	})
}

/******************************/
/*  Pending Requests handlers */
/******************************/
func (server *Server) pendingRequestsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server.getPaginatedListWithCursor(r, w, server.DB.GetPendingRequestsWithCursor)
	})
}

func (server *Server) pendingRequestBodyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idStr := mux.Vars(r)["id"]
		id, err := uuid.Parse(idStr)
		if err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't parse request ID", err)
			return
		}

		prBody, err := server.DB.GetPendingRequestBody(r.Context(), id)
		if err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't get pending request body", err)
			return
		}
		writeHTTPWithHeaders(w, http.StatusOK, prBody, map[string]string{
			"Content-Type":        "application/octet-stream",
			"Content-Disposition": fmt.Sprintf("attachment; filename=body-%s", idStr),
		})
	})
}

func (server *Server) pendingRequestHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idStr := mux.Vars(r)["id"]
		id, err := uuid.Parse(idStr)
		if err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't parse request ID", err)
			return
		}

		switch r.Method {
		case http.MethodDelete: // reject
			if err := server.DB.DeletePendingRequest(r.Context(), id); err != nil {
				server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't delete pending request", err)
				return
			}
			server.Log.Info(r, "pending request rejected")
			writeJSONOk(w, nil)

		case http.MethodPost: // approve and execute
			pendingReq, err := server.DB.GetPendingRequest(r.Context(), id)
			if err != nil {
				server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't get pending request", err)
				return
			}

			tokenInfo, ok := r.Context().Value(loggingpkg.CtxKeyTokenInfo{}).(*loggingpkg.TokenInfo)
			if !ok || tokenInfo == nil {
				server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't get token info from context")
				return
			}
			user := tokenInfo.GetHumanReadableUsername()

			// Recreate the original request and process it through the router
			reqBody := bytes.NewReader(pendingReq.Body)
			ctx := r.Context()
			ctx = context.WithValue(ctx, loggingpkg.CtxKeyOriginalRequestID{}, id)

			// Remove the writeToDB flag from context to prevent double logging
			ctx = context.WithValue(ctx, loggingpkg.CtxKeyWriteLogToDB{}, false)

			// Execute the pending request using the approver's token
			if r.URL.Query().Get("useOwnToken") == "true" {
				requesterUser, err := server.DB.GetPendingRequestUser(r.Context(), id)
				if err != nil {
					server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't get pending request user", err)
					return
				}
				if requesterUser == user {
					server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest,
						"cannot guarantee that requester and approver are different users")
					return
				}

				server.Log.Debug(r, "using approver's own token to execute pending request")
				pendingReq.Header.Set("Authorization", r.Header.Get("Authorization"))

			} else {
				token, ok := r.Context().Value(loggingpkg.CtxKeyToken{}).(*oidc.IDToken)
				if !ok {
					server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "missing token in context")
					return
				}

				ctx = context.WithValue(ctx, loggingpkg.CtxKeyApproverToken{}, token)
			}

			req, err := http.NewRequestWithContext(ctx, pendingReq.Method, pendingReq.URL.String(), reqBody)
			if err != nil {
				server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't create new request", err)
				return
			}
			req.Header = pendingReq.Header.Clone()

			rr := httptest.NewRecorder()
			server.Router.ServeHTTP(rr, req)

			if !(rr.Code >= 200 && rr.Code < 300) {
				server.logErrorAndWriteHTTP(w, r.WithContext(ctx), http.StatusInternalServerError,
					"pending request approved but execution failed",
					fmt.Errorf("execution failed with status code: %d", rr.Code))
				return
			}

			maps.Copy(w.Header(), rr.Header())
			w.WriteHeader(rr.Code)
			if _, err := w.Write(rr.Body.Bytes()); err != nil {
				server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError,
					"pending request approved but execution failed",
					fmt.Errorf("couldn't write response body: %w", err))
				return
			}

			if err := server.DB.DeletePendingRequest(r.Context(), id); err != nil {
				server.logErrorAndWriteHTTP(w, r.WithContext(ctx), http.StatusInternalServerError,
					"pending request approved but execution failed",
					fmt.Errorf("couldn't delete pending request: %w", err))
				return
			}

			server.Log.Info(r, "pending request approved and processed")
		}
	})
}

/******************************/
/*   Miscellaneous handlers   */
/******************************/
func (server *Server) logsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server.getPaginatedListWithCursor(r, w, server.DB.GetLogsWithCursor)
	})
}

func (server *Server) tokenHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b authpkg.TokenRequest
		if err := decodeJSONBody(r, &b); err != nil {
			server.logErrorAndWriteHTTP(w, r.WithContext(r.Context()), http.StatusBadRequest, "couldn't decode body", err)
			return
		}
		token, err := authpkg.ExchangeForToken(&b)
		if err != nil {
			server.logErrorAndWriteHTTP(w, r.WithContext(r.Context()), http.StatusUnauthorized,
				"couldn't exchange credentials for Keycloak token", err)

			if b.Jwt != "" {
				go func() {
					var claims map[string]any
					authpkg.Claims(b.Jwt, &claims)
					server.Log.Debug(r, "couldn't exchange JWT for Keycloak token",
						"claims", claims, "error", err)
				}()
			}

			return
		}

		if len(token) == 0 {
			server.logErrorAndWriteHTTP(w, r.WithContext(r.Context()), http.StatusUnauthorized,
				"empty token received from exchange", nil)
			return
		}

		writeJSONOk(w, map[string]map[string]string{
			"auth": {
				"client_token": token,
			},
		})
	})
}

func (server *Server) kubernetesJWKSHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwksURL := "https://kubernetes.default.svc.cluster.local/openid/v1/jwks"
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, jwksURL, nil)
		if err != nil {
			server.logErrorAndWriteHTTP(w, r.WithContext(r.Context()), http.StatusInternalServerError,
				"couldn't create request to Kubernetes API", err)
			return
		}

		// use the service account token to authenticate with the Kubernetes API server
		tokenBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
		if err != nil {
			server.logErrorAndWriteHTTP(w, r.WithContext(r.Context()), http.StatusInternalServerError,
				"couldn't read service account token", err)
			return
		}
		token := strings.TrimSpace(string(tokenBytes))
		req.Header.Set("Authorization", "Bearer "+token)

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			server.logErrorAndWriteHTTP(w, r.WithContext(r.Context()), http.StatusInternalServerError,
				"couldn't get response from Kubernetes API", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			server.logErrorAndWriteHTTP(w, r.WithContext(r.Context()), http.StatusInternalServerError,
				fmt.Sprintf("unexpected status code from Kubernetes API: %d", resp.StatusCode), nil)
			return
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			server.logErrorAndWriteHTTP(w, r.WithContext(r.Context()), http.StatusInternalServerError,
				"couldn't read response body from Kubernetes API", err)
			return
		}

		writeHTTPWithHeaders(w, http.StatusOK, body,
			map[string]string{"Content-Type": "application/json"})
	})
}

func (server *Server) healthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSONOk(w, map[string]any{
			"initialized":     true,
			"sealed":          false,
			"server_time_utc": time.Now().UTC().Unix(),
			"version":         server.Version,
		})
	})
}

func (server *Server) dashboardHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hasAccessToAllEnvs, accessibleEnvs, err := getAccessibleEnvs(r.Context())
		if err != nil {
			server.logErrorAndWriteHTTP(w, r,
				http.StatusInternalServerError, "couldn't get accessible environments", err)
			return
		}
		dashboard, err := server.DB.GetDashboard(r.Context(), hasAccessToAllEnvs, accessibleEnvs)
		if err != nil {
			server.logErrorAndWriteHTTP(w, r,
				http.StatusInternalServerError, "couldn't get dashboard data", err)
			return
		}
		writeJSONOk(w, dashboard)
	})
}
