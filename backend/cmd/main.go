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

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
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

	internalpkg "github.com/keyauthority/keyauthority/internal"
	cachepkg "github.com/keyauthority/keyauthority/internal/cache"
	cryptopkg "github.com/keyauthority/keyauthority/internal/crypto"
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

var (
	version       string
	enterprise    string
	logger        *loggingpkg.StdAndDBLogger
	store         *internalpkg.Store
	acmeResponder *internalpkg.ACMEResponder

	// HTTP router, made global so pendingRequestHandler can access it
	router = mux.NewRouter()

	// Cache prefix:name/id -> environment
	envCache = cachepkg.NewCache()
)

func main() {
	var err error

	// Set enterprise flag
	cryptopkg.Enterprise = enterprise == "true"

	// Ports
	httpPort := os.Getenv(envHTTPPort)
	httpsPort := os.Getenv(envHTTPSPort)
	metricsPort := os.Getenv(envMetricsPort)

	// TLS cert and key for HTTPS (optional)
	tlsCert := os.Getenv(envTLSCert)
	tlsKey := os.Getenv(envTLSKey)
	tlsEnabled := tlsCert != "" && tlsKey != ""

	// Create store
	if store, err = internalpkg.NewStore(context.Background()); err != nil {
		fmt.Printf("couldn't set up store: %v", err)
		return
	}
	defer store.Close()

	// Create logger
	if logger, err = loggingpkg.NewLogger(context.Background(), store.DB); err != nil {
		fmt.Printf("couldn't set up logger: %v", err)
		return
	}
	defer logger.Close()
	logger.InfoWithContext(context.Background(), "logger ready")

	// Set default HTTP transport
	setDefaultHttpTransport()

	// Set up the authenticator
	internalpkg.SetupAuthenticator()
	logger.InfoWithContext(context.Background(), "authenticator ready")

	// Create ACME responder
	acmeResponder = internalpkg.NewACMEResponder(store, onCertificateSigned)
	logger.InfoWithContext(context.Background(), "ACME responder ready")

	// Metrics
	metricspkg.SetupMetrics()
	startMetricsServer(metricsPort)

	// Handlers

	// ---------- Keys ---------- //
	router.Handle("/v1/keys", withAuth(
		map[string]internalpkg.Role{
			http.MethodGet:  internalpkg.RoleAny,      // get keys
			http.MethodPost: internalpkg.RoleOperator, // create key
		},
		keysHandler))

	router.Handle("/v1/keys/{id}", withAuth(
		map[string]internalpkg.Role{
			http.MethodGet:    internalpkg.RoleOperator, // get key
			http.MethodDelete: internalpkg.RoleOperator, // delete key
		},
		keyHandler))

	router.Handle("/v1/keys/{id}/ready", withAuth(
		map[string]internalpkg.Role{
			http.MethodGet: internalpkg.RoleOperator, // get key readiness
		},
		keyReadinessHandler))

	// ------------ Signers ------------ //
	router.Handle("/v1/signers", withAuth(
		map[string]internalpkg.Role{
			http.MethodGet: internalpkg.RoleAny, // get signers
		},
		signersHandler))

	router.Handle("/v1/signers/{name}", withAuth(
		map[string]internalpkg.Role{
			http.MethodPost:   internalpkg.RoleOperator, // create signer
			http.MethodDelete: internalpkg.RoleOperator, // delete signer
		},
		signerHandler))

	router.Handle("/v1/signers/{name}/private-key", withAuth(
		map[string]internalpkg.Role{
			http.MethodGet: internalpkg.RoleOperator, // get private key ID
		},
		signerPrivateKeyHandler))

	router.Handle("/v1/signers/{name}/config", withAuth(
		map[string]internalpkg.Role{
			http.MethodGet: internalpkg.RoleOperator, // get signer config
			http.MethodPut: internalpkg.RoleOperator, // update signer config
		},
		signerConfigHandler))

	router.Handle("/v1/signers/{name}/ca-chain", withAuth(
		map[string]internalpkg.Role{
			http.MethodGet: internalpkg.RoleOperator, // get CA chain
			http.MethodPut: internalpkg.RoleOperator, // update CA chain
		},
		signerCAChainHandler))

	router.Handle("/v1/signers/{name}/ca-csr", withAuth(
		map[string]internalpkg.Role{
			http.MethodGet: internalpkg.RoleOperator, // create CA CSR
		},
		signerCSRHandler))

	router.Handle("/v1/signers/{name}/sign",
		metricspkg.WithHttpMetrics("/v1/signers/{name}/sign", withAuth(
			map[string]internalpkg.Role{
				http.MethodPost: internalpkg.RoleOperator, // sign certificate
			},
			signerSignHandler)))

	router.Handle("/v1/signers/{name}/sign-document",
		metricspkg.WithHttpMetrics("/v1/signers/{name}/sign-document", withAuth(
			map[string]internalpkg.Role{
				http.MethodPost: internalpkg.RoleOperator, // sign document
			},
			signerSignDocumentHandler)))

	router.Handle("/v1/signers/{name}/revoke",
		metricspkg.WithHttpMetrics("/v1/signers/{name}/revoke", withAuth(
			map[string]internalpkg.Role{
				http.MethodPost: internalpkg.RoleOperator, // revoke certificate
			},
			signerRevokeHandler)))

	router.PathPrefix("/v1/signers/{name}/acme").Handler(
		signerACMEHandler)

	// CRL is registered on the main router only when TLS is disabled.
	// When TLS is enabled, it gets its own plain HTTP listener (see bottom of main).
	if !tlsEnabled {
		router.Handle("/v1/crl/{hashOfSignerName:.*}", signerCRLHandler)
		router.Handle("/v1/aia/{hashOfSignerName:.*}", signerAIAHandler)
		router.Handle("/v1/ocsp/{hashOfSignerName:.*}", signerOCSPHandler)
	}

	// ------------ Secrets ------------ //
	router.Handle("/v1/secrets", withAuth(
		map[string]internalpkg.Role{
			http.MethodGet: internalpkg.RoleAny, // get secrets
		},
		secretsHandler))

	router.Handle("/v1/secrets/data/{name:.+}",
		metricspkg.WithHttpMetrics("/v1/secrets/data/{name}", withAuth(
			map[string]internalpkg.Role{
				http.MethodGet: internalpkg.RoleOperator, // get secret (Hashicorp Vault compatible)
			},
			secretHandler)))

	router.Handle("/v1/secrets/{name:.+}",
		metricspkg.WithHttpMetrics("/v1/secrets/{name}", withAuth(
			map[string]internalpkg.Role{
				http.MethodGet:    internalpkg.RoleOperator, // get secret
				http.MethodPut:    internalpkg.RoleOperator, // insert secret
				http.MethodPost:   internalpkg.RoleOperator, // update secret
				http.MethodPatch:  internalpkg.RoleOperator, // patch secret
				http.MethodDelete: internalpkg.RoleOperator, // delete secret
			},
			secretHandler)))

	// ---------- Certificates ---------- //
	router.Handle("/v1/certs", withAuth(
		map[string]internalpkg.Role{
			http.MethodGet: internalpkg.RoleAny, // get certs
		},
		certsHandler))

	router.Handle("/v1/certs/{serial}/pem", withAuth(
		map[string]internalpkg.Role{
			http.MethodGet: internalpkg.RoleAny, // get cert PEM
		},
		certHandler))

	// ------------ Pending Requests ------------ //
	router.Handle("/v1/pending-requests", withAuth(
		map[string]internalpkg.Role{
			http.MethodGet: internalpkg.RoleApprover, // get pending requests
		},
		pendingRequestsHandler))

	router.Handle("/v1/pending-requests/{id}",
		metricspkg.WithHttpMetrics("/v1/pending-requests/{id}", withAuth(
			map[string]internalpkg.Role{
				http.MethodPost:   internalpkg.RoleApprover, // approve pending request
				http.MethodDelete: internalpkg.RoleApprover, // reject pending request
			},
			pendingRequestHandler)))

	router.Handle("/v1/pending-requests/{id}/body", withAuth(
		map[string]internalpkg.Role{
			http.MethodGet: internalpkg.RoleApprover, // get pending request body
		},
		pendingRequestBodyHandler))

	// ------------ Miscellaneous ------------ //
	router.Handle("/v1/logs", withAuth(
		map[string]internalpkg.Role{
			http.MethodGet: internalpkg.RoleAuditor, // get logs
		},
		logsHandler))

	router.Handle("/v1/token", tokenHandler)

	router.Handle("/v1/health", healthHandler)

	router.Handle("/v1/oidc/jwks/kubernetes", kubernetesJWKSHandler)

	// ----- Other Hashicorp Vault compatible paths ----- //
	router.Handle("/v1/auth/{mount}/login", tokenHandler)

	router.Handle("/v1/sys/health", healthHandler)

	router.PathPrefix("/v1/sys/internal/ui/mounts/").Handler(
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
	router.PathPrefix("/swagger/").Handler(
		http.StripPrefix("/swagger/", http.FileServer(http.FS(swagger.Files))))

	// ------------ Periodic Tasks ----- //
	runPeriodicTasks()

	// ------------ Start server ------------ //
	logger.InfoWithContext(context.Background(), "server started",
		"version", version, "enterprise", enterprise)

	if tlsEnabled {
		logger.InfoWithContext(context.Background(), "TLS enabled")

		// CRL, AIA, and OCSP must always be served over plain HTTP
		nonTLSRouter := mux.NewRouter()
		nonTLSRouter.Handle("/v1/crl/{hashOfSignerName:.*}", signerCRLHandler)
		nonTLSRouter.Handle("/v1/aia/{hashOfSignerName:.*}", signerAIAHandler)
		nonTLSRouter.Handle("/v1/ocsp/{hashOfSignerName:.*}", signerOCSPHandler)
		go func() {
			logger.InfoWithContext(context.Background(), "non-TLS server (CRL, AIA, OCSP) started")
			if err := http.ListenAndServe(":"+httpPort, nonTLSRouter); err != nil {
				logger.ErrorWithContext(context.Background(), "non-TLS server (CRL, AIA, OCSP) stopped", "error", err)
			}
		}()

		http.ListenAndServeTLS(":"+httpsPort, tlsCert, tlsKey, withCORS(router))
	} else {
		http.ListenAndServe(":"+httpPort, withCORS(router))
	}
}

func startMetricsServer(metricsPort string) {
	if metricsPort == "" {
		logger.WarnWithContext(context.Background(),
			"metrics server disabled: METRICS_PORT is not set")
		return
	}

	metricsRouter := mux.NewRouter()
	metricsRouter.Handle("/metrics", metricspkg.MetricsHandler())

	go func() {
		logger.InfoWithContext(context.Background(), "metrics server started")

		if err := http.ListenAndServe(":"+metricsPort, metricsRouter); err != nil {
			logger.ErrorWithContext(context.Background(),
				"metrics server stopped", "error", err)
		}
	}()
}

func runPeriodicTasks() {
	// CRL recreation
	go func() {
		intervalStr := os.Getenv(envCRLRefreshInterval)
		if intervalStr == "" {
			intervalStr = "72h"
		}
		crlRecreationInterval, err := time.ParseDuration(intervalStr)
		if err != nil {
			logger.WarnWithContext(context.Background(),
				"invalid CRL refresh interval, using default of 72h",
				"error", err, "intervalStr", intervalStr)
			crlRecreationInterval = 72 * time.Hour
		}

		ticker := time.NewTicker(crlRecreationInterval)
		defer ticker.Stop()

		for {
			successCount, failureCount, err := recreateCRLs()
			if err != nil {
				logger.WarnWithContext(context.Background(), "couldn't recreate CRLs", "error", err)
			} else {
				logger.DebugWithContext(context.Background(), "CRL recreation completed",
					"successCount", successCount, "failureCount", failureCount)
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
			logger.WarnWithContext(context.Background(),
				"invalid store cleanup interval, using default of 24h",
				"error", err, "intervalStr", intervalStr)
			storeCleanupInterval = 24 * time.Hour
		}

		time.Sleep(storeCleanupInterval) // initial delay before first cleanup
		ticker := time.NewTicker(storeCleanupInterval)
		defer ticker.Stop()

		for {
			if err := store.RunCleanupTasks(context.Background()); err != nil {
				logger.WarnWithContext(context.Background(),
					"couldn't perform store cleanup tasks", "error", err)
			} else {
				logger.DebugWithContext(context.Background(),
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
			logger.WarnWithContext(context.Background(),
				"invalid inventory refresh interval, using default of 30m",
				"error", err, "intervalStr", intervalStr)
			inventoryRefreshInterval = 30 * time.Minute
		}

		ticker := time.NewTicker(inventoryRefreshInterval)
		defer ticker.Stop()

		for {
			if err := store.RefreshInventoryMetrics(context.Background()); err != nil {
				logger.WarnWithContext(context.Background(),
					"couldn't refresh inventory metrics", "error", err)
			} else {
				logger.DebugWithContext(context.Background(),
					"inventory metrics refreshed")
			}
			<-ticker.C
		}
	}()
}

func recreateCRLs() (int, int, error) {
	ctx := context.Background()
	signers, _, _, err := store.GetSigners(ctx, true, nil, url.Values{})
	if err != nil {
		return 0, 0, err
	}

	successCount := 0
	for _, s := range signers {
		signerName := s["name"].(string)

		signer, err := store.LoadSigner(ctx, signerName)
		if err != nil {
			logger.WarnWithContext(ctx, "couldn't load signer", "signer", signerName, "error", err)
			continue
		}

		existingCRL, err := store.GetSignerCRL(ctx, signerName)
		if err != nil {
			logger.WarnWithContext(ctx, "couldn't get existing CRL", "signer", signerName, "error", err)
			continue
		}

		crl, err := signer.SignCRL(existingCRL, nil)
		if err != nil {
			logger.WarnWithContext(ctx, "couldn't create CRL", "signer", signerName, "error", err)
			continue
		}

		if err := store.SetSignerCRL(ctx, signerName, crl); err != nil {
			logger.WarnWithContext(ctx, "couldn't store CRL", "signer", signerName, "error", err)
			continue
		}

		logger.InfoWithContext(ctx, "CRL updated", "signer", signerName)
		successCount++
	}
	return successCount, len(signers) - successCount, nil
}

func setDefaultHttpTransport() {
	caPool, err := x509.SystemCertPool()
	if err != nil {
		logger.ErrorWithContext(context.Background(), "couldn't load system cert pool",
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
				logger.WarnWithContext(context.Background(), "couldn't load CA from file",
					"path", path, "error", err)
				continue
			}
			if ok := caPool.AppendCertsFromPEM(caCert); !ok {
				logger.WarnWithContext(context.Background(), "couldn't append CA from file",
					"path", path)
			}
		}
	}

	defaulTransp := http.DefaultTransport.(*http.Transport)
	if defaulTransp.TLSClientConfig == nil {
		defaulTransp.TLSClientConfig = &tls.Config{
			RootCAs: caPool,
		}
	} else {
		defaulTransp.TLSClientConfig.RootCAs = caPool
	}
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

func logErrorAndWriteHTTP(w http.ResponseWriter, r *http.Request, code int, msg string, args ...any) {
	var errors []error
	var logArgs []any
	for i := range args {
		if e, isError := args[i].(error); isError && e != nil {
			logArgs = append(logArgs, "error", e)
			errors = append(errors, e)
		}
	}

	logger.Error(r, msg, logArgs...)

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

// Hook called when a certificate is signed
func onCertificateSigned(r *http.Request, cert *x509.Certificate, comment string) {
	signerName := mux.Vars(r)["name"]
	logger.Info(r, "certificate signed",
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
		err := store.InsertCert(context.Background(), signerName, cert, comment)
		if err != nil {
			logger.Error(r, "couldn't insert certificate", "error", err)
		}
	}()
}

func getAccessibleEnvs(ctx context.Context) (bool, []string, error) {
	if roles, ok := ctx.Value(loggingpkg.CtxKeyRoles).([]string); ok {
		envs := []string{}
		for _, role := range roles {
			if role == "KEYAUTHORITY_OPERATOR" {
				return true, nil, nil // has access to all environments
			}
			if after, ok1 := strings.CutPrefix(role, "KEYAUTHORITY_OPERATOR_"); ok1 {
				envs = append(envs, after)
			}
		}
		return false, envs, nil
	}
	return false, nil, fmt.Errorf("couldn't get accessible environments: missing token roles in context")
}

func getPaginatedListWithAccessibleEnvs(
	r *http.Request,
	w http.ResponseWriter,
	getFunc func(ctx context.Context, hasAccessToAllEnvs bool, accessibleEnvs []string, filters url.Values) ([]map[string]any, int, int, error),
	countFunc func(ctx context.Context, hasAccessToAllEnvs bool, accessibleEnvs []string, filters url.Values) (int, error),
) {
	hasAccessToAllEnvs, accessibleEnvs, err := getAccessibleEnvs(r.Context())
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't get accessible environments", err)
		return
	}

	filters := r.URL.Query()

	var items []map[string]any
	var limit, offset int
	if filters.Get("totalCountOnly") != "true" {
		items, limit, offset, err = getFunc(r.Context(), hasAccessToAllEnvs, accessibleEnvs, filters)
		if err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't get items", err)
			return
		}
	}

	totalCount, err := countFunc(r.Context(), hasAccessToAllEnvs, accessibleEnvs, filters)
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't get total count", err)
		return
	}

	respPage := 1
	if limit > 0 && offset >= 0 {
		respPage = (offset / limit) + 1
	}

	writeJSONOk(w, map[string]any{
		"data":       items,
		"page":       respPage,
		"pageSize":   limit,
		"count":      len(items),
		"totalCount": totalCount,
	})
}

func getPaginatedListWithoutAccessibleEnvs(
	r *http.Request,
	w http.ResponseWriter,
	getFunc func(ctx context.Context, filters url.Values) ([]map[string]any, int, int, error),
	countFunc func(ctx context.Context, filters url.Values) (int, error),
) {
	filters := r.URL.Query()

	var items []map[string]any
	var limit, offset int
	if filters.Get("totalCountOnly") != "true" {
		var err error
		items, limit, offset, err = getFunc(r.Context(), filters)
		if err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't get items", err)
			return
		}
	}

	totalCount, err := countFunc(r.Context(), filters)
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't get total count", err)
		return
	}

	respPage := 1
	if limit > 0 && offset >= 0 {
		respPage = (offset / limit) + 1
	}

	writeJSONOk(w, map[string]any{
		"data":       items,
		"page":       respPage,
		"pageSize":   limit,
		"count":      len(items),
		"totalCount": totalCount,
	})
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

func requiresApproval(r *http.Request) bool {
	// already approved, no need for approval again
	if _, ok := r.Context().Value(loggingpkg.CtxKeyOriginalRequestID).(uuid.UUID); ok {
		return false
	}

	if isUpdateSignerRequest(r) || isSigningRequest(r) {
		cfg, err := store.GetSignerConfig(r.Context(), mux.Vars(r)["name"])
		if err != nil {
			return false
		}
		return cfg.ApprovalRequired
	}

	return false
}

func getEnvironment(r *http.Request) (string, error) {
	ctx := r.Context()

	// signer requests
	if strings.HasPrefix(r.URL.Path, "/v1/signers/") {
		signerName := mux.Vars(r)["name"]
		cacheKey := "signer:" + signerName
		if env, ok := envCache.Get(cacheKey); ok {
			logger.Debug(r, "environment cache hit", "environment", env)
			return env.(string), nil
		}

		// on create signer, derive from privateKeyID query param
		if isCreateSignerRequest(r) {
			keyID := r.URL.Query().Get("privateKeyID")
			return store.GetKeyEnvironment(ctx, keyID)
		}

		env, err := store.GetSignerEnvironment(ctx, signerName)
		if err != nil {
			return "", err
		}

		envCache.Set(cacheKey, env)
		return env, nil
	}

	// secret requests
	if strings.HasPrefix(r.URL.Path, "/v1/secrets/") {
		secretName := mux.Vars(r)["name"]
		cacheKey := "secret:" + secretName
		if env, ok := envCache.Get(cacheKey); ok {
			logger.Debug(r, "environment cache hit", "environment", env)
			return env.(string), nil
		}

		// on insert secret, derive from encryptionKeyID query param
		if isInsertSecretRequest(r) {
			keyID := r.URL.Query().Get("encryptionKeyID")
			return store.GetKeyEnvironment(ctx, keyID)
		}

		env, err := store.GetSecretEnvironment(ctx, secretName)
		if err != nil {
			return "", err
		}
		envCache.Set(cacheKey, env)
		return env, nil
	}

	// key requests
	if strings.HasPrefix(r.URL.Path, "/v1/keys/") || r.URL.Path == "/v1/keys" {
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
		if env, ok := envCache.Get(cacheKey); ok {
			logger.Debug(r, "environment cache hit", "environment", env)
			return env.(string), nil
		}

		env, err := store.GetKeyEnvironment(ctx, keyID)
		if err != nil {
			return "", fmt.Errorf("couldn't get key environment: %w", err)
		}

		envCache.Set(cacheKey, env)
		return env, nil
	}

	return "", nil
}

/******************************/
/*         Middlewares        */
/******************************/
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ignoredPaths := []string{"/v1/crl/", "/v1/aia/", "/v1/ocsp/"}
		shouldSetCORS := true
		for _, p := range ignoredPaths {
			if strings.HasPrefix(r.URL.Path, p) {
				shouldSetCORS = false
				break
			}
		}
		if shouldSetCORS {
			w.Header().Set("Access-Control-Allow-Origin", os.Getenv(envCORSOrigin))
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Vault-Token")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func withAuth(requiredRoles map[string]internalpkg.Role, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Determine required role for HTTP method
		requiredRole := internalpkg.RoleAny
		if len(requiredRoles) > 0 {
			if role, ok := requiredRoles[r.Method]; ok {
				requiredRole = role
			} else {
				logErrorAndWriteHTTP(w, r, http.StatusMethodNotAllowed, "HTTP method not allowed")
				return
			}
		}

		// Verify token
		token, err := internalpkg.VerifyToken(r)
		if err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusUnauthorized, "authentication failed", err)
			return
		}

		// Parse immutable claims once, store in context
		user, roles := loggingpkg.GetTokenInfoFromClaims(token, true)

		ctx := r.Context()
		ctx = context.WithValue(ctx, loggingpkg.CtxKeyToken, token)
		ctx = context.WithValue(ctx, loggingpkg.CtxKeyUser, user)
		ctx = context.WithValue(ctx, loggingpkg.CtxKeyRoles, roles)
		r = r.WithContext(ctx)

		// Determine environment for RBAC and logging context
		environment, err := getEnvironment(r)
		if err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't determine environment", err)
			return
		}
		if environment != "" {
			ctx = r.Context()
			ctx = context.WithValue(ctx, loggingpkg.CtxKeyEnvironment, environment)
			r = r.WithContext(ctx)
		}

		// RBAC check — use roles already extracted above
		if !internalpkg.HasRequiredRole(roles, environment, requiredRole) {
			logErrorAndWriteHTTP(w, r, http.StatusForbidden,
				"insufficient permissions", fmt.Errorf("missing required role: %d", requiredRole))
			return
		}

		logger.Debug(r, "token verified and required role satisfied")

		// Save logs to DB only after token is verified and RBAC is checked
		ctx = r.Context()
		ctx = context.WithValue(ctx, loggingpkg.CtxKeyWriteLogToDB, true)
		r = r.WithContext(ctx)

		// Prevent requester and approver from being the same user
		approverToken, ok := ctx.Value(loggingpkg.CtxKeyApproverToken).(*oidc.IDToken)
		if ok && approverToken.Subject == token.Subject && approverToken.Issuer == token.Issuer {
			logErrorAndWriteHTTP(w, r, http.StatusForbidden,
				"cannot guarantee that requester and approver are different users")
			return
		}

		// If request requires additional approval, save as pending
		if requiresApproval(r) {
			body, _ := io.ReadAll(r.Body)
			ctx = r.Context()
			requestID, err := store.InsertPendingRequest(ctx,
				&internalpkg.PendingRequestPrivate{
					Method: r.Method,
					Header: r.Header.Clone(),
					URL:    r.URL,
					Body:   body,
				}, token)
			if err != nil {
				logErrorAndWriteHTTP(w, r, http.StatusInternalServerError,
					"couldn't store pending request", err)
				return
			}

			ctx = context.WithValue(ctx, loggingpkg.CtxKeyRequestID, requestID)
			r = r.WithContext(ctx)

			logger.Info(r, "pending request created", "id", requestID)
			writeHTTPWithHeaders(w, http.StatusPreconditionRequired, []byte(requestID.String()),
				map[string]string{"Content-Type": "text/plain"})
			return
		}

		next.ServeHTTP(w, r)
	})
}

/******************************/
/*        Keys handlers       */
/******************************/
var keysHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet: // get keys
		getPaginatedListWithAccessibleEnvs(r, w, store.GetKeys, store.CountKeys)

	case http.MethodPost: // create key
		q := r.URL.Query()
		environment := q.Get("environment")
		if environment == "" {
			logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "environment query parameter is required")
			return
		}
		var cfg cryptopkg.KeyConfig
		if err := decodeJSONBody(r, &cfg); err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't decode body", err)
			return
		}

		if cfg.PKCS11Uri != "" {
			// it's an HSM key
			if cfg.PKCS11KeyUri == "" {
				// If this is an HSM key and no key URI is defined, create one with a random ID
				hsmKeyID := make([]byte, 16)
				if _, err := rand.Read(hsmKeyID); err != nil {
					logErrorAndWriteHTTP(w, r, http.StatusInternalServerError,
						"couldn't create random ID for HSM key URI", err)
					return
				}
				cfg.PKCS11KeyUri = fmt.Sprintf("pkcs11:id=%s;object=keyauthority",
					hex.EncodeToString(hsmKeyID))
			}
		}

		user, ok := r.Context().Value(loggingpkg.CtxKeyUser).(string)
		if !ok {
			logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't get user from context")
			return
		}

		keyID, err := store.CreateKey(r.Context(), environment, &cfg, user)
		if err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't create key", err)
			return
		}

		logger.Info(r, "key created",
			"keyID", keyID,
			"environment", environment,
			"config", cfg)

		writeHTTPWithHeaders(w, http.StatusCreated, []byte(keyID.String()),
			map[string]string{
				"Content-Type": "text/plain",
			})
	}
})

var keyHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	keyIDStr := mux.Vars(r)["id"]
	keyID, err := uuid.Parse(keyIDStr)
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "invalid key ID", err)
		return
	}

	switch r.Method {
	case http.MethodGet:
		key, err := store.GetKey(r.Context(), keyID)
		if err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't get key", err)
			return
		}
		writeJSONOk(w, key)

	case http.MethodDelete:
		if err := store.DeleteKey(r.Context(), keyID); err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't delete key", err)
			return
		}
		envCache.Delete("key:" + keyIDStr) // invalidate environment cache for this key
		logger.Info(r, "key deleted if existed")
		writeJSONOk(w, nil)
	}
})

var keyReadinessHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	keyIDStr := mux.Vars(r)["id"]
	keyID, err := uuid.Parse(keyIDStr)
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "invalid key ID", err)
		return
	}

	if err := store.CheckKeyReadiness(r.Context(), keyID); err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "key is not ready", err)
		return
	}

	logger.Debug(r, "key is ready")
	writeHTTP(w, http.StatusOK, nil)
})

/******************************/
/*    Certificates handlers   */
/******************************/
var certHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	serial := mux.Vars(r)["serial"]
	pem, err := store.GetCertPEM(r.Context(), serial)
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't get certificate", err)
		return
	}
	writeHTTPWithHeaders(w, http.StatusOK, pem,
		map[string]string{
			"Content-Type":        "application/x-pem-file",
			"Content-Disposition": fmt.Sprintf(`attachment; filename="%s.pem"`, serial),
		})
})

var certsHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	getPaginatedListWithAccessibleEnvs(r, w, store.GetCerts, store.CountCerts)
})

/******************************/
/*      Signers handlers      */
/******************************/

var signersHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	getPaginatedListWithAccessibleEnvs(r, w, store.GetSigners, store.CountSigners)
})

var signerHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	signerName := mux.Vars(r)["name"]

	switch r.Method {
	case http.MethodPost: // create signer
		q := r.URL.Query()
		privateKeyID := q.Get("privateKeyID")
		if privateKeyID == "" {
			logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "privateKeyID query parameter is required")
			return
		}

		keyID, err := uuid.Parse(privateKeyID)
		if err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't parse key ID", err)
			return
		}
		if _, err := store.LoadKey(r.Context(), keyID); err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't load private key", err)
			return
		}

		var cfg signerpkg.SignerConfig
		if err := decodeJSONBody(r, &cfg); err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't decode body", err)
			return
		}

		if err := store.CreateSigner(r.Context(), signerName, keyID, &cfg); err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't create signer", err)
			return
		}

		logger.Info(r, "signer created", "keyID", keyID, "config", cfg)
		writeHTTP(w, http.StatusCreated, nil)

	case http.MethodDelete: // delete signer
		if err := store.DeleteSigner(r.Context(), signerName); err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't delete signer", err)
			return
		}
		envCache.Delete("signer:" + signerName) // invalidate environment cache for this signer
		logger.Info(r, "signer deleted")
		writeJSONOk(w, nil)
	}
})

var signerPrivateKeyHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	signerName := mux.Vars(r)["name"]
	privateKeyID, err := store.GetPrivateKeyID(r.Context(), signerName)
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't get signer private key ID", err)
		return
	}
	writeHTTPWithHeaders(w, http.StatusOK, []byte(privateKeyID.String()),
		map[string]string{
			"Content-Type": "text/plain",
		})
})

var signerConfigHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	signerName := mux.Vars(r)["name"]
	switch r.Method {
	case http.MethodGet: // get signer config
		cfg, err := store.GetSignerConfig(r.Context(), signerName)
		if err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't get signer config", err)
			return
		}
		writeJSONOk(w, cfg)

	case http.MethodPut: // update signer config
		var cfg signerpkg.SignerConfig
		if err := decodeJSONBody(r, &cfg); err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't decode body", err)
			return
		}

		if err := store.SetSignerConfig(r.Context(), signerName, &cfg); err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't update signer config", err)
			return
		}

		logger.Info(r, "signer config updated", "config", cfg)
		writeJSONOk(w, nil)
	}

})

var signerCAChainHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	signerName := mux.Vars(r)["name"]
	switch r.Method {
	case http.MethodGet: // get CA chain
		caChain, err := store.GetSignerCAChain(r.Context(), signerName)
		if err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't get signer CA chain", err)
			return
		}

		writeHTTPWithHeaders(w, http.StatusOK, caChain, map[string]string{
			"Content-Type":        "application/x-pem-file",
			"Content-Disposition": "attachment; filename=ca-chain.pem",
		})

	case http.MethodPut: // update CA chain
		signer, err := store.LoadSigner(r.Context(), signerName)
		if err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't load signer", err)
			return
		}

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't read body", err)
			return
		}
		if err := signer.SetCAChain(bodyBytes); err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't assign CA chain to signer", err)
			return
		}
		if err := store.SetSignerCAChain(r.Context(), signerName, bodyBytes); err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't save CA chain", err)
			return
		}
		logger.Info(r, "CA chain updated")
		writeJSONOk(w, nil)
	}
})

var signerCSRHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	signerName := mux.Vars(r)["name"]
	signer, err := store.LoadSigner(r.Context(), signerName, signerpkg.IgnoreCAChainErrors(true))
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't load signer", err)
		return
	}

	csr, err := signer.CreateCSR()
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't create CA CSR", err)
		return
	}

	logger.Info(r, "CA CSR created")
	writeHTTPWithHeaders(w, http.StatusOK, csr, map[string]string{
		"Content-Type":        "application/x-pem-file",
		"Content-Disposition": "attachment; filename=ca-csr.pem",
	})
})

var signerSignHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	signerName := mux.Vars(r)["name"]
	signer, err := store.LoadSigner(r.Context(), signerName)
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't load signer", err)
		return
	}

	type Body struct {
		CSR     string `json:"csr"`
		TTL     string `json:"ttl"`
		Comment string `json:"comment,omitempty"`
	}
	var body Body
	if err := decodeJSONBody(r, &body); err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't decode body", err)
		return
	}

	cr, err := signerpkg.ParseCSR([]byte(body.CSR))
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't parse CSR", err)
		return
	}

	ttl, err := time.ParseDuration(body.TTL)
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't parse TTL", err)
		return
	}

	cert, fullChain, err := signer.Sign(cr, ttl)
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't sign certificate", err)
		return
	}

	onCertificateSigned(r, cert, body.Comment)

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

var signerSignDocumentHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	signerName := mux.Vars(r)["name"]
	signer, err := store.LoadSigner(r.Context(), signerName)
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't load signer", err)
		return
	}

	// check if signer supports document signing
	if signer.CA.Certificate == nil || signer.CA.Certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "signer doesn't support document signing: 'digital signature' usage is required")
		return
	}

	// parse multipart form
	if err := r.ParseMultipartForm(32 << 20); err != nil { // 32MB max memory
		logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't parse multipart form", err)
		return
	}

	file, _, err := r.FormFile("document")
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "missing document file", err)
		return
	}
	defer file.Close()

	fileBytes, err := io.ReadAll(file)
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't read document file", err)
		return
	}
	if len(fileBytes) == 0 {
		logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "empty document file")
		return
	}

	// sign the document
	signedBytes, err := signer.SignPDF(fileBytes)
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't sign document", err)
		return
	}

	h := sha256.Sum256(signedBytes)
	logger.Info(r, "document signed", "sha256", hex.EncodeToString(h[:]))

	writeHTTPWithHeaders(w, http.StatusOK, signedBytes, map[string]string{
		"Content-Disposition": `attachment; filename="signed.pdf"`,
		"Content-Type":        "application/pdf",
	})
})

var signerCRLHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	hash := mux.Vars(r)["hashOfSignerName"]
	crl, err := store.GetSignerCRLByHash(r.Context(), hash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			logErrorAndWriteHTTP(w, r, http.StatusNotFound, "CRL not found for signer", err)
		} else {
			logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't get CRL for signer", err)
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

var signerAIAHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	hash := mux.Vars(r)["hashOfSignerName"]
	caCert, err := store.GetSignerCACertByHash(r.Context(), hash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			logErrorAndWriteHTTP(w, r, http.StatusNotFound, "CA certificate not found for signer", err)
		} else {
			logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't get CA certificate for signer", err)
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

var signerOCSPHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	logErrorAndWriteHTTP(w, r, http.StatusNotImplemented, "OCSP responder is not implemented yet")
})

var signerRevokeHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	signerName := mux.Vars(r)["name"]
	signer, err := store.LoadSigner(r.Context(), signerName)
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't load signer", err)
		return
	}

	var revocationPair signerpkg.RevocationPair
	if err := decodeJSONBody(r, &revocationPair); err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't decode body", err)
		return
	}

	existingCRL, err := store.GetSignerCRL(r.Context(), signerName)
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't get existing CRL", err)
		return
	}

	crl, err := signer.SignCRL(existingCRL, []signerpkg.RevocationPair{revocationPair})
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't sign CRL", err)
		return
	}

	if err := store.SetSignerCRL(r.Context(), signerName, crl); err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't save new CRL", err)
		return
	}

	if err := store.SetCertAsRevoked(r.Context(), revocationPair.Serial); err != nil {
		logger.Warn(r, "couldn't set certificate as revoked", "error", err)
	}

	logger.Info(r, "certificate revoked",
		"serial", revocationPair.Serial, "reason", revocationPair.Reason)
	writeJSONOk(w, nil)
})

var signerACMEHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// for ACME finalize requests, we need to determine the environment for logging context
	if strings.HasSuffix(r.URL.Path, "/acme/finalize") {
		environment, err := getEnvironment(r)
		if err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't determine environment", err)
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, loggingpkg.CtxKeyEnvironment, environment)
		ctx = context.WithValue(ctx, loggingpkg.CtxKeyWriteLogToDB, true)
		r = r.WithContext(ctx)
	}

	resp, code, headers, err := acmeResponder.BuildResponse(r)
	if err != nil {
		logErrorAndWriteHTTP(w, r, code, "couldn't handle ACME request", err)
		return
	}
	if code == http.StatusCreated && strings.HasSuffix(r.URL.Path, "/new-acct") {
		logger.Info(r, "ACME account created", "uri", headers["Location"])
	}

	logger.Debug(r, "ACME request handled", "code", code)
	writeHTTPWithHeaders(w, code, resp, headers)
})

/******************************/
/*      Secrets handlers      */
/******************************/
var secretsHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	getPaginatedListWithAccessibleEnvs(r, w, store.GetSecrets, store.CountSecrets)
})

var secretHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	secretName := mux.Vars(r)["name"]

	switch r.Method {
	case http.MethodGet: // get secret
		secret, err := store.GetSecret(r.Context(), secretName)
		if err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't get secret", err)
			return
		}
		logger.Info(r, "secret read")

		switch r.URL.Query().Get("output") {
		case "shell":
			var shell strings.Builder
			data, ok := secret["data"].(map[string]string)
			if !ok {
				logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "invalid secret data type", nil)
				return
			}
			for k, v := range data {
				shell.WriteString(fmt.Sprintf(`%s='%s'`, k, v) + "\n")
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
			logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "encryptionKeyID query parameter is required for secret creation", nil)
			return
		}
		encryptionKeyID, err := uuid.Parse(encryptionKeyIDStr)
		if err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "invalid encryption key ID", err)
			return
		}

		var data map[string]string
		if err := decodeJSONBody(r, &data); err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't decode body", err)
			return
		}

		if err := store.InsertSecret(r.Context(), secretName, encryptionKeyID, data); err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't insert secret", err)
			return
		}
		logger.Info(r, "secret inserted", "encryptionKeyID", encryptionKeyID)
		writeHTTP(w, http.StatusCreated, nil)

	case http.MethodPost, http.MethodPatch: // update/patch secret
		var data map[string]string
		if err := decodeJSONBody(r, &data); err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't decode body", err)
			return
		}

		err := store.UpdateSecret(r.Context(), secretName, data, r.Method == http.MethodPatch)
		if err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't update secret", err)
			return
		}
		logger.Info(r, "secret updated/patched")
		writeJSONOk(w, nil)

	case http.MethodDelete:
		if err := store.DeleteSecret(r.Context(), secretName); err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusInternalServerError,
				"couldn't delete secret", err)
			return
		}
		envCache.Delete("secret:" + secretName) // invalidate environment cache for this secret
		logger.Info(r, "secret deleted if existed")
		writeJSONOk(w, nil)
	}
})

/******************************/
/*  Pending Requests handlers */
/******************************/
var pendingRequestsHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	getPaginatedListWithoutAccessibleEnvs(r, w, store.GetPendingRequests, store.CountPendingRequests)
})

var pendingRequestBodyHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	idStr := mux.Vars(r)["id"]
	id, err := uuid.Parse(idStr)
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't parse request ID", err)
		return
	}

	prBody, err := store.GetPendingRequestBody(r.Context(), id)
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't get pending request body", err)
		return
	}
	writeHTTPWithHeaders(w, http.StatusOK, prBody, map[string]string{
		"Content-Type":        "application/octet-stream",
		"Content-Disposition": fmt.Sprintf("attachment; filename=body-%s", idStr),
	})
})

var pendingRequestHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	idStr := mux.Vars(r)["id"]
	id, err := uuid.Parse(idStr)
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't parse request ID", err)
		return
	}

	switch r.Method {
	case http.MethodDelete: // reject
		if err := store.DeletePendingRequest(r.Context(), id); err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't delete pending request", err)
			return
		}
		logger.Info(r, "pending request rejected")
		writeJSONOk(w, nil)

	case http.MethodPost: // approve and execute
		pendingReq, err := store.GetPendingRequest(r.Context(), id)
		if err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't get pending request", err)
			return
		}

		user, ok := r.Context().Value(loggingpkg.CtxKeyUser).(string)
		if !ok {
			logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "missing user in context")
			return
		}

		// Recreate the original request and process it through the router
		reqBody := bytes.NewReader(pendingReq.Body)
		ctx := r.Context()
		ctx = context.WithValue(ctx, loggingpkg.CtxKeyOriginalRequestID, id)

		// Remove the writeToDB flag from context to prevent double logging
		ctx = context.WithValue(ctx, loggingpkg.CtxKeyWriteLogToDB, false)

		// Execute the pending request using the approver's token
		if useOwnToken := r.URL.Query().Get("useOwnToken"); useOwnToken == "true" {
			prList, _, _, err := store.GetPendingRequests(r.Context(),
				url.Values{
					"id":     []string{id.String()},
					"limit":  []string{"1"},
					"offset": []string{"0"},
				})
			if err != nil || len(prList) != 1 {
				logErrorAndWriteHTTP(w, r, http.StatusInternalServerError,
					"couldn't get pending request info", err)
				return
			}
			if requesterUser, ok := prList[0]["tokenInfo"].(map[string]any)["user"].(string); !ok || requesterUser == user {
				logErrorAndWriteHTTP(w, r, http.StatusBadRequest,
					"cannot guarantee that requester and approver are different users")
				return
			}

			logger.Debug(r, "using approver's own token to execute pending request")
			pendingReq.Header.Set("Authorization", r.Header.Get("Authorization"))

		} else {
			token, ok := r.Context().Value(loggingpkg.CtxKeyToken).(*oidc.IDToken)
			if !ok {
				logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "missing token in context")
				return
			}

			ctx = context.WithValue(ctx, loggingpkg.CtxKeyApproverToken, token)
		}

		req, err := http.NewRequestWithContext(ctx, pendingReq.Method, pendingReq.URL.String(), reqBody)
		if err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't create new request", err)
			return
		}
		req.Header = pendingReq.Header.Clone()

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if !(rr.Code >= 200 && rr.Code < 300) {
			logErrorAndWriteHTTP(w, r.WithContext(ctx), http.StatusInternalServerError,
				"pending request approved but execution failed", err)
			return
		}

		maps.Copy(w.Header(), rr.Header())
		w.WriteHeader(rr.Code)
		if _, err := w.Write(rr.Body.Bytes()); err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusInternalServerError,
				"pending request approved but execution failed",
				fmt.Errorf("couldn't write response body: %w", err))
			return
		}

		if err := store.DeletePendingRequest(r.Context(), id); err != nil {
			logErrorAndWriteHTTP(w, r.WithContext(ctx), http.StatusInternalServerError,
				"pending request approved but execution failed",
				fmt.Errorf("couldn't delete pending request: %w", err))
			return
		}

		logger.Info(r, "pending request approved and processed")
	}
})

/******************************/
/*   Miscellaneous handlers   */
/******************************/
var logsHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	getPaginatedListWithoutAccessibleEnvs(r, w, store.GetLogs, store.CountLogs)
})

var tokenHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	var b internalpkg.TokenRequest
	if err := decodeJSONBody(r, &b); err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't decode body", err)
		return
	}
	token, err := internalpkg.ExchangeForToken(&b)
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusUnauthorized,
			"couldn't exchange credentials for Keycloak token", err)

		if b.Jwt != "" {
			go func() {
				var claims map[string]any
				internalpkg.Claims(b.Jwt, &claims)
				logger.Debug(r, "couldn't exchange JWT for Keycloak token",
					"claims", claims, "error", err)
			}()
		}

		return
	}

	if len(token) == 0 {
		logErrorAndWriteHTTP(w, r, http.StatusUnauthorized,
			"empty token received from exchange", nil)
		return
	}

	writeJSONOk(w, map[string]map[string]string{
		"auth": {
			"client_token": token,
		},
	})
})

var kubernetesJWKSHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	jwksURL := "https://kubernetes.default.svc.cluster.local/openid/v1/jwks"
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, jwksURL, nil)
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusInternalServerError,
			"couldn't create request to Kubernetes API", err)
		return
	}

	// use the service account token to authenticate with the Kubernetes API server
	tokenBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusInternalServerError,
			"couldn't read service account token", err)
		return
	}
	token := strings.TrimSpace(string(tokenBytes))
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusInternalServerError,
			"couldn't get response from Kubernetes API", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logErrorAndWriteHTTP(w, r, http.StatusInternalServerError,
			fmt.Sprintf("unexpected status code from Kubernetes API: %d", resp.StatusCode), nil)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusInternalServerError,
			"couldn't read response body from Kubernetes API", err)
		return
	}

	writeHTTPWithHeaders(w, http.StatusOK, body,
		map[string]string{"Content-Type": "application/json"})
})

var healthHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	writeJSONOk(w, map[string]any{
		"enterprise":      cryptopkg.Enterprise,
		"initialized":     true,
		"sealed":          false,
		"server_time_utc": time.Now().UTC().Unix(),
		"version":         version,
	})
})
