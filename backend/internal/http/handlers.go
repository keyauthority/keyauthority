// Copyright 2025 KeyAuthority.

package http

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	authpkg "github.com/keyauthority/keyauthority/internal/auth"
	cryptopkg "github.com/keyauthority/keyauthority/internal/crypto"
	eventspkg "github.com/keyauthority/keyauthority/internal/events"
	loggingpkg "github.com/keyauthority/keyauthority/internal/logging"
	signerpkg "github.com/keyauthority/keyauthority/internal/signer"
)

/******************************/
/*        Keys handlers       */
/******************************/
func (server *Server) handleGetKeysOrCreateKey(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet: // get keys
		server.getPaginatedListWithAccessibleEnvsAndCursor(r, w, server.db.GetKeysWithCursor)

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

		keyID, err := server.db.CreateKey(r.Context(), environment, &cfg, user)
		if err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't create key", err)
			return
		}

		server.log.Info(r, "key created",
			"keyID", keyID,
			"environment", environment,
			"config", cfg)

		writeHTTPWithHeaders(w, http.StatusCreated, []byte(keyID.String()),
			map[string]string{
				"Content-Type": "text/plain",
			})
	}
}

func (server *Server) handleGetKey(w http.ResponseWriter, r *http.Request) {
	keyIDStr := mux.Vars(r)["id"]
	keyID, err := uuid.Parse(keyIDStr)
	if err != nil {
		server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "invalid key ID", err)
		return
	}

	switch r.Method {
	case http.MethodGet:
		key, err := server.db.GetKey(r.Context(), keyID)
		if err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't get key", err)
			return
		}
		writeJSONOk(w, key)

	case http.MethodDelete:
		if err := server.db.DeleteKey(r.Context(), keyID); err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't delete key", err)
			return
		}
		server.envCache.Delete("key:" + keyIDStr) // invalidate environment cache for this key
		server.log.Info(r, "key deleted if existed")
		writeJSONOk(w, nil)
	}
}

func (server *Server) handleGetKeyReadiness(w http.ResponseWriter, r *http.Request) {
	keyIDStr := mux.Vars(r)["id"]
	keyID, err := uuid.Parse(keyIDStr)
	if err != nil {
		server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "invalid key ID", err)
		return
	}

	if err := server.db.CheckKeyReadiness(r.Context(), keyID); err != nil {
		server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "key is not ready", err)
		return
	}

	server.log.Debug(r, "key is ready")
	writeHTTP(w, http.StatusOK, nil)
}

/******************************/
/*      Signers handlers      */
/******************************/
func (server *Server) handleGetSigners(w http.ResponseWriter, r *http.Request) {
	server.getPaginatedListWithAccessibleEnvsAndCursor(r, w, server.db.GetSignersWithCursor)
}

func (server *Server) handleCreateOrDeleteSigner(w http.ResponseWriter, r *http.Request) {
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
		if _, err := server.db.LoadKey(r.Context(), keyID); err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't load private key", err)
			return
		}

		var cfg signerpkg.SignerConfig
		if err := decodeJSONBody(r, &cfg); err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't decode body", err)
			return
		}

		if err := server.db.CreateSigner(r.Context(), signerName, keyID, &cfg); err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't create signer", err)
			return
		}

		server.log.Info(r, "signer created", "keyID", keyID, "config", cfg)
		writeHTTP(w, http.StatusCreated, nil)

	case http.MethodDelete: // delete signer
		if err := server.db.DeleteSigner(r.Context(), signerName); err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't delete signer", err)
			return
		}
		server.envCache.Delete("signer:" + signerName) // invalidate environment cache for this signer
		server.log.Info(r, "signer deleted")
		writeJSONOk(w, nil)
	}
}

func (server *Server) handleGetSignerPrivateKeyID(w http.ResponseWriter, r *http.Request) {
	signerName := mux.Vars(r)["name"]
	privateKeyID, err := server.db.GetPrivateKeyID(r.Context(), signerName)
	if err != nil {
		server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't get signer private key ID", err)
		return
	}
	writeHTTPWithHeaders(w, http.StatusOK, []byte(privateKeyID.String()),
		map[string]string{
			"Content-Type": "text/plain",
		})
}

func (server *Server) handleGetOrUpdateSignerConfig(w http.ResponseWriter, r *http.Request) {
	signerName := mux.Vars(r)["name"]
	switch r.Method {
	case http.MethodGet: // get signer config
		cfg, err := server.db.GetSignerConfig(r.Context(), signerName)
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

		if err := server.db.SetSignerConfig(r.Context(), signerName, &cfg); err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't update signer config", err)
			return
		}

		server.log.Info(r, "signer config updated", "config", cfg)
		writeJSONOk(w, nil)
	}

}

func (server *Server) handleGetOrUpdateSignerCAChain(w http.ResponseWriter, r *http.Request) {
	signerName := mux.Vars(r)["name"]
	switch r.Method {
	case http.MethodGet: // get CA chain
		caChain, err := server.db.GetSignerCAChain(r.Context(), signerName)
		if err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't get signer CA chain", err)
			return
		}

		writeHTTPWithHeaders(w, http.StatusOK, caChain, map[string]string{
			"Content-Type":        "application/x-pem-file",
			"Content-Disposition": "attachment; filename=ca-chain.pem",
		})

	case http.MethodPut: // update CA chain
		signer, err := server.db.LoadSigner(r.Context(), signerName)
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
		if err := server.db.SetSignerCAChain(r.Context(), signerName, bodyBytes); err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't save CA chain", err)
			return
		}
		server.log.Info(r, "CA chain updated")
		writeJSONOk(w, nil)
	}
}

func (server *Server) handleCreateSignerCARequest(w http.ResponseWriter, r *http.Request) {
	signerName := mux.Vars(r)["name"]
	signer, err := server.db.LoadSigner(r.Context(), signerName, signerpkg.IgnoreCAChainErrors(true))
	if err != nil {
		server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't load signer", err)
		return
	}

	csr, err := signer.CreateCSR()
	if err != nil {
		server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't create CA CSR", err)
		return
	}

	server.log.Info(r, "CA CSR created")
	writeHTTPWithHeaders(w, http.StatusOK, csr, map[string]string{
		"Content-Type":        "application/x-pem-file",
		"Content-Disposition": "attachment; filename=ca-csr.pem",
	})
}

func (server *Server) handleSignerSign(w http.ResponseWriter, r *http.Request) {
	signerName := mux.Vars(r)["name"]
	signer, err := server.db.LoadSigner(r.Context(), signerName)
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

	eventspkg.OnCertificateSigned(r, server.log, server.db, cert, body.Comment)

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

func (server *Server) handleSignerRevoke(w http.ResponseWriter, r *http.Request) {
	signerName := mux.Vars(r)["name"]
	signer, err := server.db.LoadSigner(r.Context(), signerName)
	if err != nil {
		server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't load signer", err)
		return
	}

	var revocationPair signerpkg.RevocationPair
	if err := decodeJSONBody(r, &revocationPair); err != nil {
		server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't decode body", err)
		return
	}

	existingCRL, err := server.db.GetSignerCRL(r.Context(), signerName)
	if err != nil {
		server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't get existing CRL", err)
		return
	}

	crl, err := signer.SignCRL(existingCRL, []signerpkg.RevocationPair{revocationPair})
	if err != nil {
		server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't sign CRL", err)
		return
	}

	if err := server.db.SetSignerCRL(r.Context(), signerName, crl); err != nil {
		server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't save new CRL", err)
		return
	}

	if err := server.db.SetCertAsRevoked(r.Context(), revocationPair.Serial); err != nil {
		server.log.Warn(r, "couldn't set certificate as revoked", "error", err)
	}

	server.log.Info(r, "certificate revoked",
		"serial", revocationPair.Serial, "reason", revocationPair.Reason)
	writeJSONOk(w, nil)
}

func (server *Server) handleGetSignerCRL(w http.ResponseWriter, r *http.Request) {
	hash := mux.Vars(r)["hashOfSignerName"]
	crl, err := server.db.GetSignerCRLByHash(r.Context(), hash)
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
}

func (server *Server) handleGetSignerAIA(w http.ResponseWriter, r *http.Request) {
	hash := mux.Vars(r)["hashOfSignerName"]
	caCert, err := server.db.GetSignerCACertByHash(r.Context(), hash)
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
}

func (server *Server) handleSignerACME(w http.ResponseWriter, r *http.Request) {
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

	resp, code, headers, err := server.acme.BuildResponse(r)
	if err != nil {
		server.logErrorAndWriteHTTP(w, r, code, "couldn't handle ACME request", err)
		return
	}
	if code == http.StatusCreated && strings.HasSuffix(r.URL.Path, "/new-acct") {
		server.log.Info(r, "ACME account created", "uri", headers["Location"])
	}

	server.log.Debug(r, "ACME request handled", "code", code)
	writeHTTPWithHeaders(w, code, resp, headers)
}

/******************************/
/*      Secrets handlers      */
/******************************/
func (server *Server) handleGetSecrets(w http.ResponseWriter, r *http.Request) {
	server.getPaginatedListWithAccessibleEnvsAndCursor(r, w, server.db.GetSecretsWithCursor)
}

func (server *Server) handleGetOrUpdateOrDeleteSecret(w http.ResponseWriter, r *http.Request) {
	secretName := mux.Vars(r)["name"]

	switch r.Method {
	case http.MethodGet: // get secret
		secret, err := server.db.GetSecret(r.Context(), secretName)
		if err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't get secret", err)
			return
		}
		server.log.Info(r, "secret read")

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

		if err := server.db.InsertSecret(r.Context(), secretName, encryptionKeyID, data); err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't insert secret", err)
			return
		}
		server.log.Info(r, "secret inserted", "encryptionKeyID", encryptionKeyID)
		writeHTTP(w, http.StatusCreated, nil)

	case http.MethodPost, http.MethodPatch: // update/patch secret
		var data map[string]string
		if err := decodeJSONBody(r, &data); err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't decode body", err)
			return
		}

		err := server.db.UpdateSecret(r.Context(), secretName, data, r.Method == http.MethodPatch)
		if err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError, "couldn't update secret", err)
			return
		}
		server.log.Info(r, "secret updated/patched")
		writeJSONOk(w, nil)

	case http.MethodDelete:
		if err := server.db.DeleteSecret(r.Context(), secretName); err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusInternalServerError,
				"couldn't delete secret", err)
			return
		}
		server.envCache.Delete("secret:" + secretName) // invalidate environment cache for this secret
		server.log.Info(r, "secret deleted if existed")
		writeJSONOk(w, nil)
	}
}

/******************************/
/*    Certificates handlers   */
/******************************/
func (server *Server) handleGetCerts(w http.ResponseWriter, r *http.Request) {
	server.getPaginatedListWithAccessibleEnvsAndCursor(r, w, server.db.GetCertsWithCursor)
}

func (server *Server) handleGetCertPEM(w http.ResponseWriter, r *http.Request) {
	serial := mux.Vars(r)["serial"]
	pem, err := server.db.GetCertPEM(r.Context(), serial)
	if err != nil {
		server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't get certificate", err)
		return
	}
	writeHTTPWithHeaders(w, http.StatusOK, pem,
		map[string]string{
			"Content-Type":        "application/x-pem-file",
			"Content-Disposition": fmt.Sprintf(`attachment; filename="%s.pem"`, serial),
		})
}

/******************************/
/*   Miscellaneous handlers   */
/******************************/
func (server *Server) handleGetLogs(w http.ResponseWriter, r *http.Request) {
	server.getPaginatedListWithCursor(r, w, server.db.GetLogsWithCursor)
}

func (server *Server) handleGetToken(w http.ResponseWriter, r *http.Request) {
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
				server.log.Debug(r, "couldn't exchange JWT for Keycloak token",
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
}

func (server *Server) handleGetKubernetesJWKS(w http.ResponseWriter, r *http.Request) {
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
}

func (server *Server) handleGetHealthStatus(w http.ResponseWriter, r *http.Request) {
	writeJSONOk(w, map[string]any{
		"initialized":     true,
		"sealed":          false,
		"server_time_utc": time.Now().UTC().Unix(),
		"version":         server.version,
	})
}

func (server *Server) handleGetDashboard(w http.ResponseWriter, r *http.Request) {
	hasAccessToAllEnvs, accessibleEnvs, err := getAccessibleEnvs(r.Context())
	if err != nil {
		server.logErrorAndWriteHTTP(w, r,
			http.StatusInternalServerError, "couldn't get accessible environments", err)
		return
	}
	dashboard, err := server.db.GetDashboard(r.Context(), hasAccessToAllEnvs, accessibleEnvs)
	if err != nil {
		server.logErrorAndWriteHTTP(w, r,
			http.StatusInternalServerError, "couldn't get dashboard data", err)
		return
	}
	writeJSONOk(w, dashboard)
}
