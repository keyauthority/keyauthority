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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"github.com/keyauthority/keyauthority/swagger"

	authpkg "github.com/keyauthority/keyauthority/internal/auth"
	cachepkg "github.com/keyauthority/keyauthority/internal/cache"
	databasepkg "github.com/keyauthority/keyauthority/internal/database"
	loggingpkg "github.com/keyauthority/keyauthority/internal/logging"
	metricspkg "github.com/keyauthority/keyauthority/internal/metrics"
	signerpkg "github.com/keyauthority/keyauthority/internal/signer"
)

const (
	envVersion                  = "VERSION"
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
	version        string
	log            *loggingpkg.StdAndDBLogger
	db             *databasepkg.Database
	acme           *ACMEResponder
	envCache       *cachepkg.Cache // Cache prefix:name/id -> environment
	handler        *mux.Router
	metricsHandler *mux.Router
	nonTLSHandler  *mux.Router // needed for CRL and AIA endpoints when TLS is enabled
}

func NewServer() *Server {
	handler := mux.NewRouter()
	nonTLSHandler := handler
	if os.Getenv(envTLSKey) != "" && os.Getenv(envTLSCert) != "" {
		nonTLSHandler = mux.NewRouter()
	}

	return &Server{
		version:        os.Getenv(envVersion),
		envCache:       cachepkg.NewCache(),
		handler:        handler,
		nonTLSHandler:  nonTLSHandler,
		metricsHandler: mux.NewRouter(),
	}
}

func (server *Server) ConnectDatabase(ctx context.Context) {
	db, err := databasepkg.NewDatabase(ctx)
	if err != nil {
		fmt.Printf("couldn't connect to database: %v", err)
		return
	}
	server.db = db
}

func (server *Server) CreateLogger(ctx context.Context) {
	log, err := loggingpkg.NewLogger(ctx, server.db.DB)
	if err != nil {
		fmt.Printf("couldn't set up logger: %v", err)
		return
	}
	server.log = log
	server.log.InfoWithContext(ctx, "logger ready")
}

func (server *Server) SetDefaultHttpTransport(ctx context.Context) {
	caPool, err := x509.SystemCertPool()
	if err != nil {
		server.log.ErrorWithContext(ctx, "couldn't load system cert pool",
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
				server.log.WarnWithContext(ctx, "couldn't load CA from file",
					"path", path, "error", err)
				continue
			}
			if ok := caPool.AppendCertsFromPEM(caCert); !ok {
				server.log.WarnWithContext(ctx, "couldn't append CA from file",
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

func (server *Server) CreateAuthenticator(ctx context.Context) {
	authpkg.SetupAuthenticator()
	server.log.InfoWithContext(ctx, "authenticator ready")
}

func (server *Server) CreateACMEResponder(ctx context.Context) {
	server.acme = NewACMEResponder(server.db, server.onCertificateSigned())
	server.log.InfoWithContext(ctx, "ACME responder ready")
}

func (server *Server) SetHandlers() {
	// ---------- Keys ---------- //
	server.handler.Handle("/v1/keys", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet:  authpkg.RoleAny,      // get keys
			http.MethodPost: authpkg.RoleOperator, // create key
		},
		server.keysHandler()))

	server.handler.Handle("/v1/keys/{id}", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet:    authpkg.RoleOperator, // get key
			http.MethodDelete: authpkg.RoleOperator, // delete key
		},
		server.keyHandler()))

	server.handler.Handle("/v1/keys/{id}/ready", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleOperator, // get key readiness
		},
		server.keyReadinessHandler()))

	// ------------ Signers ------------ //
	server.handler.Handle("/v1/signers", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleAny, // get signers
		},
		server.signersHandler()))

	server.handler.Handle("/v1/signers/{name}", server.withAuth(
		map[string]authpkg.Role{
			http.MethodPost:   authpkg.RoleOperator, // create signer
			http.MethodDelete: authpkg.RoleOperator, // delete signer
		},
		server.signerHandler()))

	server.handler.Handle("/v1/signers/{name}/private-key", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleOperator, // get private key ID
		},
		server.signerPrivateKeyHandler()))

	server.handler.Handle("/v1/signers/{name}/config", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleOperator, // get signer config
			http.MethodPut: authpkg.RoleOperator, // update signer config
		},
		server.signerConfigHandler()))

	server.handler.Handle("/v1/signers/{name}/ca-chain", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleOperator, // get CA chain
			http.MethodPut: authpkg.RoleOperator, // update CA chain
		},
		server.signerCAChainHandler()))

	server.handler.Handle("/v1/signers/{name}/ca-csr", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleOperator, // create CA CSR
		},
		server.signerCSRHandler()))

	server.handler.Handle("/v1/signers/{name}/sign",
		metricspkg.WithHttpMetrics("/v1/signers/{name}/sign", server.withAuth(
			map[string]authpkg.Role{
				http.MethodPost: authpkg.RoleOperator, // sign certificate
			},
			server.signerSignHandler())))

	server.handler.Handle("/v1/signers/{name}/revoke",
		metricspkg.WithHttpMetrics("/v1/signers/{name}/revoke", server.withAuth(
			map[string]authpkg.Role{
				http.MethodPost: authpkg.RoleOperator, // revoke certificate
			},
			server.signerRevokeHandler())))

	server.handler.PathPrefix("/v1/signers/{name}/acme").Handler(
		server.signerACMEHandler())

	server.nonTLSHandler.Handle("/v1/crl/{hashOfSignerName:.*}", server.signerCRLHandler())
	server.nonTLSHandler.Handle("/v1/aia/{hashOfSignerName:.*}", server.signerAIAHandler())

	// ------------ Secrets ------------ //
	server.handler.Handle("/v1/secrets", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleAny, // get secrets
		},
		server.secretsHandler()))

	server.handler.Handle("/v1/secrets/data/{name:.+}",
		metricspkg.WithHttpMetrics("/v1/secrets/data/{name}", server.withAuth(
			map[string]authpkg.Role{
				http.MethodGet: authpkg.RoleOperator, // get secret (Hashicorp Vault compatible)
			},
			server.secretHandler())))

	server.handler.Handle("/v1/secrets/{name:.+}",
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
	server.handler.Handle("/v1/certs", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleAny, // get certs
		},
		server.certsHandler()))

	server.handler.Handle("/v1/certs/{serial}/pem", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleAny, // get cert PEM
		},
		server.certHandler()))

	// ------------ Pending Requests ------------ //
	server.handler.Handle("/v1/pending-requests", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleApprover, // get pending requests
		},
		server.pendingRequestsHandler()))

	server.handler.Handle("/v1/pending-requests/{id}",
		metricspkg.WithHttpMetrics("/v1/pending-requests/{id}", server.withAuth(
			map[string]authpkg.Role{
				http.MethodPost:   authpkg.RoleApprover, // approve pending request
				http.MethodDelete: authpkg.RoleApprover, // reject pending request
			},
			server.pendingRequestHandler())))

	server.handler.Handle("/v1/pending-requests/{id}/body", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleApprover, // get pending request body
		},
		server.pendingRequestBodyHandler()))

	// ------------ Miscellaneous ------------ //
	server.handler.Handle("/v1/dashboard", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleAny,
		},
		server.dashboardHandler()))

	server.handler.Handle("/v1/logs", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleAuditor, // get logs
		},
		server.logsHandler()))

	server.handler.Handle("/v1/token", server.tokenHandler())

	server.handler.Handle("/v1/health", server.healthHandler())

	server.handler.Handle("/v1/oidc/jwks/kubernetes", server.kubernetesJWKSHandler())

	// ----- Other Hashicorp Vault compatible paths ----- //
	server.handler.Handle("/v1/auth/{mount}/login", server.tokenHandler())

	server.handler.Handle("/v1/sys/health", server.healthHandler())

	server.handler.PathPrefix("/v1/sys/internal/ui/mounts/").Handler(
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
	server.handler.PathPrefix("/swagger/").Handler(
		http.StripPrefix("/swagger/", http.FileServer(http.FS(swagger.Files))))
}

func (server *Server) ListenAndServe(ctx context.Context) {
	// metrics
	metricspkg.SetupMetrics()
	server.metricsHandler.Handle("/metrics", metricspkg.MetricsHandler())

	go func() {
		port := os.Getenv(envMetricsPort)
		server.log.InfoWithContext(ctx, "metrics server starting", "port", port)
		if err := http.ListenAndServe(":"+port, server.metricsHandler); err != nil {
			server.log.ErrorWithContext(ctx, "couldn't start metrics server", "port", port, "error", err)
		}
	}()

	// HTTP server (it's also main server if TLS is not enabled)
	go func() {
		port := os.Getenv(envHTTPPort)
		server.log.InfoWithContext(ctx, "HTTP server starting", "port", port)

		if err := http.ListenAndServe(":"+port,
			server.withSecurityHeaders(server.withCORS(server.nonTLSHandler))); err != nil {
			server.log.ErrorWithContext(ctx,
				"couldn't start HTTP server",
				"port", port,
				"error", err,
			)
		}
	}()

	// HTTPS server (if TLS is enabled)
	tlsCert := os.Getenv(envTLSCert)
	tlsKey := os.Getenv(envTLSKey)
	if tlsCert == "" || tlsKey == "" {
		return
	}

	go func() {
		port := os.Getenv(envHTTPSPort)
		server.log.InfoWithContext(ctx, "HTTPS server starting", "port", port)

		if err := http.ListenAndServeTLS(
			":"+port,
			tlsCert,
			tlsKey,
			server.withSecurityHeaders(server.withCORS(server.handler)),
		); err != nil {
			server.log.ErrorWithContext(ctx,
				"couldn't start HTTPS server",
				"port", port,
				"error", err,
			)
		}
	}()
}

func (server *Server) RunPeriodicTasks(ctx context.Context) {
	// CRL recreation
	go func() {
		intervalStr := os.Getenv(envCRLRefreshInterval)
		if intervalStr == "" {
			intervalStr = "72h"
		}
		crlRecreationInterval, err := time.ParseDuration(intervalStr)
		if err != nil {
			server.log.WarnWithContext(ctx,
				"invalid CRL refresh interval, using default of 72h",
				"error", err, "intervalStr", intervalStr)
			crlRecreationInterval = 72 * time.Hour
		}

		ticker := time.NewTicker(crlRecreationInterval)
		defer ticker.Stop()

		for {
			successCount, failureCount, err := server.recreateCRLs(ctx)
			if err != nil {
				server.log.WarnWithContext(ctx, "couldn't recreate CRLs", "error", err)
			} else {
				server.log.DebugWithContext(ctx, "CRL recreation completed",
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
			server.log.WarnWithContext(ctx,
				"invalid store cleanup interval, using default of 24h",
				"error", err, "intervalStr", intervalStr)
			storeCleanupInterval = 24 * time.Hour
		}

		time.Sleep(storeCleanupInterval) // initial delay before first cleanup
		ticker := time.NewTicker(storeCleanupInterval)
		defer ticker.Stop()

		for {
			if err := server.db.RunCleanupTasks(ctx); err != nil {
				server.log.WarnWithContext(ctx,
					"couldn't perform store cleanup tasks", "error", err)
			} else {
				server.log.DebugWithContext(ctx,
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
			server.log.WarnWithContext(ctx,
				"invalid inventory refresh interval, using default of 30m",
				"error", err, "intervalStr", intervalStr)
			inventoryRefreshInterval = 30 * time.Minute
		}

		ticker := time.NewTicker(inventoryRefreshInterval)
		defer ticker.Stop()

		for {
			if err := server.db.RefreshInventoryMetrics(ctx); err != nil {
				server.log.WarnWithContext(ctx,
					"couldn't refresh inventory metrics", "error", err)
			} else {
				server.log.DebugWithContext(ctx,
					"inventory metrics refreshed")
			}
			<-ticker.C
		}
	}()
}

func (server *Server) Close() {
	if server.db != nil {
		server.db.Close()
	}
	if server.log != nil {
		server.log.Close()
	}
}

/***********************************/
/* 	  Non-exported Functions       */
/***********************************/

func (server *Server) recreateCRLs(ctx context.Context) (int, int, error) {
	signers, err := server.db.GetAllSigners(ctx)
	if err != nil {
		return 0, 0, err
	}

	successCount := 0
	for _, signerName := range signers {
		signer, err := server.db.LoadSigner(ctx, signerName)
		if err != nil {
			server.log.WarnWithContext(ctx, "couldn't load signer", "signer", signerName, "error", err)
			continue
		}

		existingCRL, err := server.db.GetSignerCRL(ctx, signerName)
		if err != nil {
			server.log.WarnWithContext(ctx, "couldn't get existing CRL", "signer", signerName, "error", err)
			continue
		}

		crl, err := signer.SignCRL(existingCRL, nil)
		if err != nil {
			server.log.WarnWithContext(ctx, "couldn't create CRL", "signer", signerName, "error", err)
			continue
		}

		if err := server.db.SetSignerCRL(ctx, signerName, crl); err != nil {
			server.log.WarnWithContext(ctx, "couldn't store CRL", "signer", signerName, "error", err)
			continue
		}

		server.log.InfoWithContext(ctx, "CRL updated", "signer", signerName)
		successCount++
	}
	return successCount, len(signers) - successCount, nil
}

func writeHTTP(w http.ResponseWriter, code int, b []byte) {
	w.WriteHeader(code)
	w.Write(b)
}

func writeHTTPWithHeaders(w http.ResponseWriter, code int, b []byte, headers map[string]string) {
	if len(headers) > 0 {
		for k, v := range headers {
			w.Header().Set(k, v)
		}
	}
	writeHTTP(w, code, b)
}

func writeJSONOk(w http.ResponseWriter, data any) {
	var b []byte
	if data != nil {
		var err error
		b, err = json.Marshal(data)
		if err != nil {
			writeHTTP(w, http.StatusInternalServerError, nil)
			return
		}
	}
	writeHTTPWithHeaders(w, http.StatusOK, b,
		map[string]string{"Content-Type": "application/json"})
}

func decodeJSONBody(r *http.Request, dst any) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("couldn't read body: %w", err)
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("couldn't unmarshal body as JSON: %w", err)
	}
	return nil
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

	server.log.Error(r, msg, logArgs...)

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

func (server *Server) getEnvironment(r *http.Request) (string, error) {
	ctx := r.Context()

	// signer requests
	if strings.HasPrefix(r.URL.Path, "/v1/signers/") {
		signerName := mux.Vars(r)["name"]
		cacheKey := "signer:" + signerName
		if env, ok := server.envCache.Get(cacheKey); ok {
			server.log.Debug(r, "environment cache hit", "environment", env)
			return env.(string), nil
		}

		// on create signer, derive from privateKeyID query param
		if isCreateSignerRequest(r) {
			keyID := r.URL.Query().Get("privateKeyID")
			return server.db.GetKeyEnvironment(ctx, keyID)
		}

		env, err := server.db.GetSignerEnvironment(ctx, signerName)
		if err != nil {
			return "", err
		}

		server.envCache.Set(cacheKey, env)
		return env, nil
	}

	// secret requests
	if strings.HasPrefix(r.URL.Path, "/v1/secrets/") {
		secretName := mux.Vars(r)["name"]
		cacheKey := "secret:" + secretName
		if env, ok := server.envCache.Get(cacheKey); ok {
			server.log.Debug(r, "environment cache hit", "environment", env)
			return env.(string), nil
		}

		// on insert secret, derive from encryptionKeyID query param
		if isInsertSecretRequest(r) {
			keyID := r.URL.Query().Get("encryptionKeyID")
			return server.db.GetKeyEnvironment(ctx, keyID)
		}

		env, err := server.db.GetSecretEnvironment(ctx, secretName)
		if err != nil {
			return "", err
		}
		server.envCache.Set(cacheKey, env)
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
		if env, ok := server.envCache.Get(cacheKey); ok {
			server.log.Debug(r, "environment cache hit", "environment", env)
			return env.(string), nil
		}

		env, err := server.db.GetKeyEnvironment(ctx, keyID)
		if err != nil {
			return "", fmt.Errorf("couldn't get key environment: %w", err)
		}

		server.envCache.Set(cacheKey, env)
		return env, nil
	}

	return "", nil
}

func getAccessibleEnvs(ctx context.Context) (bool, []string, error) {
	tokenInfo, ok := ctx.Value(loggingpkg.CtxKeyTokenInfo{}).(*loggingpkg.TokenInfo)
	if !ok || tokenInfo == nil {
		return false, nil, fmt.Errorf("couldn't get accessible environments: missing token info in context")
	}

	envs := []string{}
	for _, role := range tokenInfo.Roles {
		if role == "KEYAUTHORITY_OPERATOR" {
			return true, nil, nil // has access to all environments
		}
		if after, ok1 := strings.CutPrefix(role, "KEYAUTHORITY_OPERATOR_"); ok1 {
			envs = append(envs, after)
		}
	}
	return false, envs, nil
}

func isCreateKeyRequest(r *http.Request) bool {
	return r.Method == http.MethodPost && r.URL.Path == "/v1/keys"
}

func isCreateSignerRequest(r *http.Request) bool {
	return r.Method == http.MethodPost &&
		r.URL.Path == fmt.Sprintf("/v1/signers/%s", mux.Vars(r)["name"])
}

func isUpdateSignerRequest(r *http.Request) bool {
	signerName := mux.Vars(r)["name"]
	pathPreffix := fmt.Sprintf("/v1/signers/%s", signerName)
	return r.Method != http.MethodGet &&
		(pathPreffix+"/config" == r.URL.Path || pathPreffix+"/ca-chain" == r.URL.Path)
}

func isSigningRequest(r *http.Request) bool {
	signerName := mux.Vars(r)["name"]
	pathPreffix := fmt.Sprintf("/v1/signers/%s", signerName)
	return r.Method != http.MethodGet && (pathPreffix+"/sign" == r.URL.Path ||
		pathPreffix+"/sign-document" == r.URL.Path ||
		pathPreffix+"/revoke" == r.URL.Path ||
		strings.HasPrefix(r.URL.Path, pathPreffix+"/acme/finalize"))
}

func isInsertSecretRequest(r *http.Request) bool {
	return r.Method == http.MethodPut &&
		r.URL.Path == fmt.Sprintf("/v1/secrets/%s", mux.Vars(r)["name"])
}

// Hook called when a certificate is signed
func (server *Server) onCertificateSigned() func(r *http.Request, cert *x509.Certificate, comment string) {
	return func(r *http.Request, cert *x509.Certificate, comment string) {
		signerName := mux.Vars(r)["name"]
		server.log.Info(r, "certificate signed",
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
			err := server.db.InsertCert(context.Background(), signerName, cert, comment)
			if err != nil {
				server.log.Error(r, "couldn't insert certificate", "error", err)
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
		cfg, err := server.db.GetSignerConfig(r.Context(), mux.Vars(r)["name"])
		if err != nil {
			return false
		}
		return cfg.ApprovalRequired
	}

	return false
}
