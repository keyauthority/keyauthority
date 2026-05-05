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
	"encoding/base64"
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
	cryptopkg "github.com/keyauthority/keyauthority/internal/crypto"
	loggingpkg "github.com/keyauthority/keyauthority/internal/logging"
	signerpkg "github.com/keyauthority/keyauthority/internal/signer"
)

const (
	envPort       = "PORT"
	envCORSOrigin = "CORS_ORIGIN"
	envTruststore = "TRUSTSTORE"
)

var (
	version       string
	enterprise    string
	port          string
	logger        *loggingpkg.StdAndDBLogger
	store         *internalpkg.Store
	authenticator *internalpkg.Authenticator
	acmeResponder *internalpkg.ACMEResponder

	// HTTP router -made global so pendingRequestHandler can access it
	router = mux.NewRouter()

	// cache environments for paths, to avoid hitting the store on every request
	envCache = internalpkg.NewCache(make(map[string]any))

	// hash of signer names to signer names
	signerNameHashes = internalpkg.NewCache(make(map[string]any))
)

func main() {
	var err error

	// Set enterprise flag
	cryptopkg.Enterprise = enterprise == "true"

	// Port
	port = os.Getenv(envPort)

	// Create store
	if store, err = internalpkg.NewStore(context.Background()); err != nil {
		fmt.Printf("couldn't set up store: %v", err)
		return
	}

	// Create logger
	if logger, err = loggingpkg.NewLogger(context.Background(), store.DB); err != nil {
		fmt.Printf("couldn't set up logger: %v", err)
		return
	}
	defer logger.Close()
	logger.InfoWithContext(context.Background(), false, "logger ready")

	// Set default HTTP transport
	setDefaultHttpTransport()

	// Set up authenticator (first time, next will be in goroutine)
	if err := setupAuthenticator(); err != nil {
		logger.ErrorWithContext(context.Background(), false,
			"couldn't set up authenticator", "error", err)
		return
	}
	logger.InfoWithContext(context.Background(), false, "authenticator ready")

	// Create ACME responder
	acmeResponder = internalpkg.NewACMEResponder(store, onCertificateSigned)
	logger.InfoWithContext(context.Background(), false, "ACME responder ready")

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

	router.Handle("/v1/signers/{name}/sign", withAuth(
		map[string]internalpkg.Role{
			http.MethodPost: internalpkg.RoleOperator, // sign certificate
		},
		signerSignHandler))

	router.Handle("/v1/signers/{name}/sign-document", withAuth(
		map[string]internalpkg.Role{
			http.MethodPost: internalpkg.RoleOperator, // sign document
		},
		signerSignDocumentHandler))

	router.Handle("/v1/signers/{name}/revoke", withAuth(
		map[string]internalpkg.Role{
			http.MethodPost: internalpkg.RoleOperator, // revoke certificate
		},
		signerRevokeHandler))

	router.PathPrefix("/v1/signers/{name}/acme").Handler(
		signerACMEHandler)

	router.Handle("/v1/crl/{hashOfSignerName:.*}", signerCRLHandler)

	// ------------ Secrets ------------ //
	router.Handle("/v1/secrets", withAuth(
		map[string]internalpkg.Role{
			http.MethodGet: internalpkg.RoleAny, // get secrets
		},
		secretsHandler))

	router.Handle("/v1/secrets/data/{name:.+}", withAuth(
		map[string]internalpkg.Role{
			http.MethodGet: internalpkg.RoleOperator, // get secret (Hashicorp Vault compatible)
		},
		secretHandler))

	router.Handle("/v1/secrets/{name:.+}", withAuth(
		map[string]internalpkg.Role{
			http.MethodGet:    internalpkg.RoleOperator, // get secret
			http.MethodPut:    internalpkg.RoleOperator, // insert secret
			http.MethodPost:   internalpkg.RoleOperator, // update secret
			http.MethodPatch:  internalpkg.RoleOperator, // patch secret
			http.MethodDelete: internalpkg.RoleOperator, // delete secret
		},
		secretHandler))

	// ------------ Pending Requests ------------ //
	router.Handle("/v1/pending-requests", withAuth(
		map[string]internalpkg.Role{
			http.MethodGet: internalpkg.RoleAuthorizer, // get pending requests
		},
		pendingRequestsHandler))

	router.Handle("/v1/pending-requests/{id}", withAuth(
		map[string]internalpkg.Role{
			http.MethodPost:   internalpkg.RoleAuthorizer, // approve pending request
			http.MethodDelete: internalpkg.RoleAuthorizer, // reject pending request
		},
		pendingRequestHandler))

	router.Handle("/v1/pending-requests/{id}/body", withAuth(
		map[string]internalpkg.Role{
			http.MethodGet: internalpkg.RoleAuthorizer, // get pending request body
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

	// ----- Start Periodic Tasks ----- //
	startPeriodicTasks()

	// ------------ Start server ------------ //
	logger.InfoWithContext(context.Background(), false, "server started",
		"port", port, "version", version, "enterprise", enterprise)

	http.ListenAndServe(":"+port, withCORS(router))
}

func saveSignerNameHash(signerName string) {
	hash := sha256.Sum256([]byte(signerName))
	hashStr := base64.URLEncoding.EncodeToString(hash[:])
	signerNameHashes.Set(hashStr[:32], signerName)
	logger.DebugWithContext(context.Background(),
		"stored hash of signer name for CRL access",
		"signerName", signerName, "hash", hashStr[:32])
}

func getSignerNameFromHash(hash string) string {
	if signerName, exists := signerNameHashes.Get(hash); exists {
		return signerName.(string)
	}
	return ""
}

func startPeriodicTasks() {
	// ------- Periodic CRL Creation ------- //
	go func() {
		ticker := time.NewTicker(72 * time.Hour)
		defer ticker.Stop()

		for {
			if err := recreateAllCRLs(); err != nil {
				logger.WarnWithContext(context.Background(), false, "couldn't recreate CRLs",
					"error", err)
			}
			<-ticker.C
		}
	}()

	// ------ Periodic Authenticator Reloading ------ //
	go func() {
		interval := 30 * time.Minute

		time.Sleep(interval)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			if err := setupAuthenticator(); err != nil {
				logger.ErrorWithContext(context.Background(), false, "couldn't reload authenticator",
					"error", err)
			}
			<-ticker.C
		}
	}()

	// ------ Periodic Store Ops ------ //
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		for {
			if err := store.PeriodicOps(context.Background()); err != nil {
				logger.WarnWithContext(context.Background(), false, "couldn't perform periodic store ops",
					"error", err)
			}
			<-ticker.C
		}
	}()
}

func setupAuthenticator() error {
	ctx := context.Background()
	newAuthenticator, logEntries, err := internalpkg.NewAuthenticator(ctx)
	if err != nil {
		return err
	}
	for _, entry := range logEntries {
		logger.LogWithContext(ctx, entry)
	}
	authenticator = newAuthenticator
	return nil
}

func setDefaultHttpTransport() {
	caPool, err := x509.SystemCertPool()
	if err != nil {
		logger.ErrorWithContext(context.Background(), false, "couldn't load system cert pool",
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
				logger.WarnWithContext(context.Background(), false, "couldn't load CA from file",
					"path", path, "error", err)
				continue
			}
			if ok := caPool.AppendCertsFromPEM(caCert); !ok {
				logger.WarnWithContext(context.Background(), false, "couldn't append CA from file",
					"path", path)
			}
		}
	}
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
		RootCAs: caPool,
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
	saveErr := false
	for i := range args {
		if e, isError := args[i].(error); isError && e != nil {
			logArgs = append(logArgs, "error", e)
			errors = append(errors, e)
			saveErr = saveErr || saveErrorLogToDB(r)
		}
	}

	logger.Error(r, saveErr, msg, logArgs...)

	var m struct {
		Errors []string `json:"errors"`
	}
	m.Errors = []string{msg}
	for _, err := range errors {
		m.Errors = append(m.Errors, err.Error())
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

// hook to run when a certificate is signed
func onCertificateSigned(r *http.Request, cert *x509.Certificate) error {
	signerName := mux.Vars(r)["name"]
	logger.Info(r, true, "certificate signed",
		slog.String("serial", signerpkg.BigIntToString(cert.SerialNumber)),
		slog.String("signerName", signerName),
		slog.String("cn", cert.Subject.CommonName),
		slog.Any("dns", cert.DNSNames),
		slog.Any("notBefore", cert.NotBefore),
		slog.Any("notAfter", cert.NotAfter),
	)
	return store.InsertCert(r.Context(), signerName, cert)
}

func recreateAllCRLs() error {
	ctx := context.Background()
	signers, _, _, err := store.GetSigners(ctx, true, nil, url.Values{})
	if err != nil {
		return err
	}

	for _, s := range signers {
		signerName := s["name"].(string)
		saveSignerNameHash(signerName)

		signer, err := store.LoadSigner(ctx, signerName)
		if err != nil {
			logger.WarnWithContext(ctx, false, "couldn't load signer", "signer", signerName, "error", err)
			continue
		}

		crl, err := signer.SignCRL(nil)
		if err != nil {
			logger.WarnWithContext(ctx, false, "couldn't create CRL", "signer", signerName, "error", err)
			continue
		}

		if err := store.SetSignerCRL(ctx, signerName, crl); err != nil {
			logger.WarnWithContext(ctx, false, "couldn't store CRL", "signer", signerName, "error", err)
		}

		logger.InfoWithContext(ctx, false, "CRL updated", "signer", signerName)
	}

	return nil
}

func getAccessibleEnvs(ctx context.Context) (bool, []string, error) {
	if token, ok := ctx.Value(loggingpkg.CtxKeyToken).(*oidc.IDToken); ok {
		if providerIdx, ok := ctx.Value(loggingpkg.CtxKeyProviderIndex).(int); ok {
			roles := authenticator.ExtractRoles(token, providerIdx)
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
	}
	return false, nil, fmt.Errorf("couldn't get accessible environments: missing token or provider index")
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
	items, limit, offset, err := getFunc(r.Context(), hasAccessToAllEnvs, accessibleEnvs, filters)
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't get items", err)
		return
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
	items, limit, offset, err := getFunc(r.Context(), filters)
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't get items", err)
		return
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

func isUpdateSecretRequest(r *http.Request) bool {
	return r.Method != http.MethodGet &&
		r.Method != http.MethodPut &&
		r.URL.Path == fmt.Sprintf("/v1/secrets/%s", mux.Vars(r)["name"])
}

func isGetSecretRequest(r *http.Request) bool {
	secretName := mux.Vars(r)["name"]
	return r.Method == http.MethodGet &&
		(r.URL.Path == fmt.Sprintf("/v1/secrets/%s", secretName) ||
			strings.HasPrefix(r.URL.Path, fmt.Sprintf("/v1/secrets/data/%s", secretName)))
}

func saveErrorLogToDB(r *http.Request) bool {
	// save error log to DB if the request is authenticated with a token (not a pending request or other non-authenticated request)
	if _, ok := r.Context().Value(loggingpkg.CtxKeyToken).(*oidc.IDToken); ok {
		return isUpdateSignerRequest(r) || isSigningRequest(r) || isUpdateSecretRequest(r) || isGetSecretRequest(r)
	}
	return false
}

func requiresAuthorization(r *http.Request) bool {
	// already authorized
	if _, ok := r.Context().Value(loggingpkg.CtxKeyOriginalRequestID).(uuid.UUID); ok {
		return false
	}

	/*if environment, ok := r.Context().Value(loggingpkg.CtxKeyEnvironment).(string); ok {
		if isProtectedEnvironment(environment) {
			return isUpdateSecretRequest(r) || isUpdateSignerRequest(r)
		}
	}*/

	if isUpdateSignerRequest(r) || isSigningRequest(r) {
		cfg, err := store.GetSignerConfig(r.Context(), mux.Vars(r)["name"])
		if err != nil {
			return false
		}
		return cfg.AuthzRequired
	}

	return false
}

func getEnvironment(r *http.Request) (string, error) {
	// derive environment, used for RBAC
	// if it's a create key request, get environment from query parameter
	// for other requests, get key ID from path or store, and then get environment from store using key ID
	environment := ""
	if env, exists := envCache.Get(r.URL.Path); exists {
		environment = env.(string)
	} else if isCreateKeyRequest(r) {
		environment = r.URL.Query().Get("environment")
	} else {
		ctx := r.Context()
		keyIDStr := ""
		keyID := uuid.Nil

		// if it's a request related to a specific key, get key ID from path
		if strings.HasPrefix(r.URL.Path, "/v1/keys/") {
			keyIDStr = mux.Vars(r)["id"]
		}

		// for signer-related requests, get the private key ID
		// from query parameter (for create signer) or from the store (for other requests)
		if strings.HasPrefix(r.URL.Path, "/v1/signers/") {
			if isCreateSignerRequest(r) {
				keyIDStr = r.URL.Query().Get("privateKeyID")
			} else {
				privateKeyID, err := store.GetPrivateKeyID(ctx, mux.Vars(r)["name"])
				if err != nil {
					return "", fmt.Errorf("couldn't get signer private key ID: %w", err)
				}
				keyID = privateKeyID
			}
		}

		// for secrets-related requests, get the encryption key ID
		// from query parameter (for insert secret) or from the store (for other requests)
		if strings.HasPrefix(r.URL.Path, "/v1/secrets/") {
			if isInsertSecretRequest(r) {
				keyIDStr = r.URL.Query().Get("encryptionKeyID")
			} else {
				encryptionKeyID, err := store.GetEncryptionKeyID(ctx, mux.Vars(r)["name"])
				if err != nil {
					return "", fmt.Errorf("couldn't get encryption key ID: %w", err)
				}
				keyID = encryptionKeyID
			}
		}

		// if keyID is still nil and keyIDStr is not empty,
		// it means the key ID was provided as a query parameter - try to parse it
		if keyIDStr != "" && keyID == uuid.Nil {
			var err error
			keyID, err = uuid.Parse(keyIDStr)
			if err != nil {
				return "", fmt.Errorf("invalid key ID: %w", err)
			}
		}

		// if we have a key ID, get the environment from the store
		if keyID != uuid.Nil {
			env, err := store.GetKeyEnvironment(ctx, keyID)
			if err != nil {
				return "", fmt.Errorf("couldn't get key environment: %w", err)
			}
			environment = env
		}

		if environment != "" {
			envCache.Set(r.URL.Path, environment)
		}
	}
	return environment, nil
}

/******************************/
/*         Middlewares        */
/******************************/
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/crl/") {
			w.Header().Set("Access-Control-Allow-Origin", os.Getenv(envCORSOrigin))
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Requested-With")
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
		if len(requiredRoles) > 0 {
			if _, ok := requiredRoles[r.Method]; !ok {
				logErrorAndWriteHTTP(w, r, http.StatusMethodNotAllowed, "HTTP method not allowed")
				return
			}
		}
		var ctx context.Context

		// determine environment for request, to include in logging context and for RBAC
		environment, err := getEnvironment(r)
		if err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't determine environment", err)
			return
		}
		if environment != "" {
			ctx = r.Context()
			ctx = context.WithValue(ctx, loggingpkg.CtxKeyEnvironment, environment)
			r = r.WithContext(ctx)
			logger.Debug(r, "determined request environment")
		}

		// authenticate and get token and provider index for logging context
		token, logEntries, providerIDx, err := authenticator.Authenticate(r, requiredRoles)
		for _, entry := range logEntries {
			logger.LogWithContext(r.Context(), entry)
		}

		if errors.Is(err, internalpkg.ErrUnauthorized) {
			logErrorAndWriteHTTP(w, r, http.StatusUnauthorized, "authentication failed", err)
			return
		}

		ctx = r.Context()
		ctx = context.WithValue(ctx, loggingpkg.CtxKeyToken, token)
		ctx = context.WithValue(ctx, loggingpkg.CtxKeyProviderIndex, providerIDx)
		r = r.WithContext(ctx)

		if errors.Is(err, internalpkg.ErrForbidden) {
			logErrorAndWriteHTTP(w, r, http.StatusForbidden, "insufficient permissions", err)
			return
		}

		if err != nil { // this case shouldn't happen
			logErrorAndWriteHTTP(w, r, http.StatusInternalServerError,
				"authentication failed with unexpected error", err)
			return
		}

		logger.Debug(r, "authenticated request made")

		authorizerToken, ok := ctx.Value(loggingpkg.CtxKeyAuthorizerToken).(*oidc.IDToken)
		if ok && authorizerToken.Subject == token.Subject && authorizerToken.Issuer == token.Issuer {
			logErrorAndWriteHTTP(w, r, http.StatusForbidden,
				"cannot guarantee that requester and authorizer are different users")
			return
		}

		// if the request requires additional authorization
		// save it as pending and return the request ID to the client
		if requiresAuthorization(r) {
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

			logger.Info(r, true, "pending request created", "id", requestID)
			writeHTTPWithHeaders(w, http.StatusPreconditionRequired, []byte(requestID.String()),
				map[string]string{
					"Content-Type": "text/plain",
				})
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
				// if the key is of type HSM and key URI is not defined, lets create it with a random ID
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

		keyID, err := store.CreateKey(r.Context(), environment, &cfg)
		if err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't create key", err)
			return
		}

		logger.Info(r, true, "key created",
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
		logger.Info(r, true, "key deleted if existed")
		writeJSONOk(w, nil)
	}
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

		saveSignerNameHash(signerName)
		logger.Info(r, true, "signer created", "keyID", keyID, "config", cfg)
		writeHTTP(w, http.StatusCreated, nil)

	case http.MethodDelete: // delete signer
		if err := store.DeleteSigner(r.Context(), signerName); err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't delete signer", err)
			return
		}
		logger.Info(r, true, "signer deleted")
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

		logger.Info(r, true, "signer config updated", "config", cfg)
		writeJSONOk(w, nil)
	}

})

var signerCAChainHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	signerName := mux.Vars(r)["name"]
	switch r.Method {
	case http.MethodGet: // get CA chain
		crl, err := store.GetSignerCAChain(r.Context(), signerName)
		if err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't get signer CA chain", err)
			return
		}

		writeHTTPWithHeaders(w, http.StatusOK, crl, map[string]string{
			"Content-Type":        "application/x-pem-file",
			"Content-Disposition": fmt.Sprintf(`attachment; filename="%s-ca-chain.pem"`, signerName),
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
		logger.Info(r, true, "CA chain updated")
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

	logger.Info(r, true, "CA CSR created")
	writeHTTPWithHeaders(w, http.StatusOK, csr, map[string]string{
		"Content-Type":        "application/x-pem-file",
		"Content-Disposition": fmt.Sprintf(`attachment; filename="%s-ca-csr.pem"`, signerName),
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
		CSR string `json:"csr"`
		TTL string `json:"ttl"`
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

	if err := onCertificateSigned(r, cert); err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "onCertificateSigned hook failed", err)
		return
	}

	switch r.URL.Query().Get("output") {
	case "pem":
		writeHTTPWithHeaders(w, http.StatusOK, []byte(strings.Join(fullChain, "\n")),
			map[string]string{
				"Content-Type": "application/x-pem-file",
				"Content-Disposition": fmt.Sprintf(`attachment; filename="%s.pem"`,
					signerpkg.BigIntToString(cert.SerialNumber)),
			})

	default:
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
	}
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

	ttlStr := r.FormValue("ttl")
	var ttl time.Duration
	if ttlStr != "" {
		ttl, err = time.ParseDuration(ttlStr)
		if err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "invalid TTL", err)
			return
		}
	} else {
		if signer.CA.Certificate == nil {
			logErrorAndWriteHTTP(w, r, http.StatusBadRequest,
				"signer doesn't have a certificate, TTL must be specified")
			return
		}
		// default TTL is until the end of the signer's certificate validity
		ttl = time.Until(signer.CA.Certificate.NotAfter)
	}

	// sign the document
	signedBytes, err := signer.SignPDF(fileBytes, ttl)
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't sign document", err)
		return
	}

	h := sha256.Sum256(signedBytes)
	logger.Info(r, true, "document signed", "sha256", hex.EncodeToString(h[:]))

	writeHTTPWithHeaders(w, http.StatusOK, signedBytes, map[string]string{
		"Content-Disposition": `attachment; filename="signed.pdf"`,
		"Content-Type":        "application/pdf",
	})
})

var signerCRLHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	var crl []byte

	hash := mux.Vars(r)["hashOfSignerName"]
	signerName := getSignerNameFromHash(hash)
	if signerName != "" {
		if crl1, err := store.GetSignerCRL(r.Context(), signerName); err == nil {
			crl = crl1
		}
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

var signerRevokeHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	signerName := mux.Vars(r)["name"]
	signer, err := store.LoadSigner(r.Context(), signerName)
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't load signer", err)
		return
	}

	var body struct {
		Serial string `json:"serial"`
	}
	if err := decodeJSONBody(r, &body); err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't decode body", err)
		return
	}

	der, err := signer.SignCRL([]string{body.Serial})
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't sign CRL", err)
		return
	}

	if err := store.SetSignerCRL(r.Context(), signerName, der); err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't save new CRL", err)
		return
	}

	if err := store.SetCertAsRevoked(r.Context(), body.Serial); err != nil {
		logger.Warn(r, false, "couldn't set certificate as revoked", "error", err)
	}

	logger.Info(r, true, "certificate revoked", "serial", body.Serial)
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
		if environment != "" {
			ctx := r.Context()
			ctx = context.WithValue(ctx, loggingpkg.CtxKeyEnvironment, environment)
			r = r.WithContext(ctx)
			logger.Debug(r, "determined request environment")
		}
	}

	resp, code, headers, err := acmeResponder.BuildResponse(r)
	if err != nil {
		logErrorAndWriteHTTP(w, r, code, "couldn't handle ACME request", err)
		return
	}
	if code == http.StatusCreated && strings.HasSuffix(r.URL.Path, "/new-acct") {
		logger.Info(r, true, "ACME account created", "uri", headers["Location"])
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
		logger.Info(r, true, "secret read")

		switch r.URL.Query().Get("output") {
		case "shell":
			var shell strings.Builder
			data, ok := secret["data"].(map[string]string)
			if !ok {
				logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "invalid secret data type", nil)
				return
			}
			for k, v := range data {
				shell.WriteString(fmt.Sprintf(`%s='%s'`, k, v) + "\n")
			}
			writeHTTP(w, http.StatusOK, []byte(shell.String()))

		default:
			// for Hashicop-style response, we need to add an extra 'data' layer in the response
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
		logger.Info(r, true, "secret inserted", "encryptionKeyID", encryptionKeyID)
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
		logger.Info(r, true, "secret updated/patched")
		writeJSONOk(w, nil)

	case http.MethodDelete:
		if err := store.DeleteSecret(r.Context(), secretName); err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusInternalServerError,
				"couldn't delete secret", err)
			return
		}
		logger.Info(r, true, "secret deleted if existed")
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
		logger.Info(r, true, "pending request rejected")
		writeJSONOk(w, nil)

	case http.MethodPost: // authorize
		pendingReq, err := store.GetPendingRequest(r.Context(), id)
		if err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't get pending request", err)
			return
		}

		token, ok := r.Context().Value(loggingpkg.CtxKeyToken).(*oidc.IDToken)
		if !ok {
			logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "missing token in context")
			return
		}

		// re-create the original request and process it through the router
		reqBody := bytes.NewReader(pendingReq.Body)
		ctx := r.Context()
		ctx = context.WithValue(ctx, loggingpkg.CtxKeyOriginalRequestID, id)

		// logic for executing request with own token
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
			if requesterUser, ok := prList[0]["tokenInfo"].(map[string]any)["user"].(string); !ok || requesterUser == loggingpkg.ExtractUser(token) {
				logErrorAndWriteHTTP(w, r, http.StatusBadRequest,
					"cannot guarantee that requester and authorizer are different users")
				return
			}

			logger.Info(r, false, "using authorizer's own token to execute pending request")
			pendingReq.Header.Set("Authorization", r.Header.Get("Authorization"))

		} else {
			ctx = context.WithValue(ctx, loggingpkg.CtxKeyAuthorizerToken, token)
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
				"pending request authorized but failed", err)
			return
		}

		maps.Copy(w.Header(), rr.Header())
		w.WriteHeader(rr.Code)
		if _, err := w.Write(rr.Body.Bytes()); err != nil {
			logErrorAndWriteHTTP(w, r, http.StatusInternalServerError,
				"pending request authorized but failed", fmt.Errorf("couldn't write response body: %w", err))
			return
		}

		if err := store.DeletePendingRequest(r.Context(), id); err != nil {
			logErrorAndWriteHTTP(w, r.WithContext(ctx), http.StatusInternalServerError,
				"pending request authorized but failed", fmt.Errorf("couldn't delete pending request: %w", err))
			return
		}

		logger.Info(r, false, "pending request authorized and processed")
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
	token, err := authenticator.GetToken(&b)
	if err != nil {
		logErrorAndWriteHTTP(w, r, http.StatusUnauthorized,
			"couldn't exchange credentials for Keycloak token", err)
		return
	}

	if len(token) == 0 {
		logErrorAndWriteHTTP(w, r, http.StatusUnauthorized,
			"empty token received from OIDC provider")
		return
	}

	writeJSONOk(w, map[string]map[string]string{
		"auth": {
			"client_token": token,
		},
	})
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
