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

package acme

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/gorilla/mux"
	databasepkg "github.com/keyauthority/keyauthority/internal/database"
	eventspkg "github.com/keyauthority/keyauthority/internal/events"
	loggingpkg "github.com/keyauthority/keyauthority/internal/logging"
)

const (
	envServerURL      = "URL"
	envTSMustBeAgreed = "ACME_TERMS_OF_SERVICE_MUST_BE_AGREED"
)

var (
	jsonHeader = map[string]string{"Content-Type": "application/json"}
)

type Service struct {
	baseURL        string
	log            *loggingpkg.Logger
	database       *databasepkg.Database
	orderStore     *OrderStore
	challengeStore *ChallengeStore
}

func NewService(log *loggingpkg.Logger, db *databasepkg.Database) *Service {
	return &Service{
		baseURL:  os.Getenv(envServerURL),
		log:      log,
		database: db,
		orderStore: &OrderStore{
			orders: make(map[string]*Order),
		},
		challengeStore: &ChallengeStore{
			challenges: make(map[string]*Challenge),
		},
	}
}

func (a *Service) RunCleanup(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.cleanUpExpiredChallenges()
			a.cleanUpExpiredOrders()
		}
	}
}

func (a *Service) BuildResponse(r *http.Request) ([]byte, int, map[string]string, error) {
	name := mux.Vars(r)["name"]
	pathSuffix := strings.TrimPrefix(r.URL.Path, "/v1/signers/"+name+"/acme")

	toJSON := func(data any) []byte {
		b, _ := json.Marshal(data)
		return b
	}

	switch pathSuffix {
	case "/.well-known/acme-directory", "/directory":
		return toJSON(map[string]string{
			"newAccount": a.baseURL + "/v1/signers/" + name + "/acme/new-acct",
			"newOrder":   a.baseURL + "/v1/signers/" + name + "/acme/new-order",
			"newNonce":   a.baseURL + "/v1/signers/" + name + "/acme/new-nonce",
			"finalize":   a.baseURL + "/v1/signers/" + name + "/acme/finalize",
		}), http.StatusOK, jsonHeader, nil

	case "/new-acct":
		type NewAccountPayload struct {
			Contact              []string `json:"contact,omitempty"`
			TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed,omitempty"`
			OnlyReturnExisting   bool     `json:"onlyReturnExisting,omitempty"`
		}
		var accountPayload NewAccountPayload

		// New account, so no keyID required
		publicKey, err := a.validateRequest(r, &accountPayload, false)
		if err != nil {
			return nil, http.StatusBadRequest, jsonHeader, fmt.Errorf("JWS validation failed: %v", err)
		}

		// Generate account ID and store the key
		accountID := keyID(publicKey)
		accountURI := a.baseURL + "/v1/signers/" + name + "/acme/acct/" + accountID

		if accountPayload.OnlyReturnExisting {
			_, err := a.database.GetACMEAccount(accountURI)
			if err != nil {
				return nil, http.StatusNotFound, jsonHeader, errors.New("account does not exist")
			}
			return toJSON(map[string]any{
				"status":  "valid",
				"contact": accountPayload.Contact,
				"orders":  a.baseURL + "/v1/signers/" + name + "/acme/orders",
			}), http.StatusOK, map[string]string{
				"Location":     accountURI,
				"Content-Type": "application/json",
				"Replay-Nonce": generateNonce(),
			}, nil
		}

		if os.Getenv(envTSMustBeAgreed) == "true" && !accountPayload.TermsOfServiceAgreed {
			return nil, http.StatusBadRequest, jsonHeader,
				errors.New("termsOfServiceAgreed must be true")
		}

		if err := a.database.InsertACMEAccount(accountURI, publicKey); err != nil {
			return nil, http.StatusInternalServerError, jsonHeader,
				fmt.Errorf("failed to store account: %v", err)
		}

		return toJSON(map[string]any{
			"status":  "valid",
			"contact": accountPayload.Contact,
			"orders":  a.baseURL + "/v1/signers/" + name + "/acme/orders",
		}), http.StatusCreated, map[string]string{
			"Location":     accountURI,
			"Content-Type": "application/json",
			"Replay-Nonce": generateNonce(),
		}, nil

	case "/acct":
		return toJSON(map[string]any{
			"status":  "valid",
			"contact": []string{"mailto:keyauthority@outlook.com"},
			"orders":  a.baseURL + "/v1/signers/" + name + "/acme/orders",
		}), http.StatusOK, jsonHeader, nil

	case "/new-nonce":
		return []byte{}, http.StatusOK, map[string]string{
			"Replay-Nonce":  generateNonce(),
			"Cache-Control": "no-store",
		}, nil

	case "/new-order":
		type OrderPayload struct {
			NotAfter    string `json:"notAfter,omitempty"`
			Identifiers []struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"identifiers"`
		}
		var orderPayload OrderPayload

		publicKey, err := a.validateRequest(r, &orderPayload, true)
		if err != nil {
			return nil, http.StatusBadRequest, jsonHeader, fmt.Errorf("JWS validation failed: %v", err)
		}

		// Generate the JWK thumbprint for this account
		thumbprint, err := jwkThumbprint(publicKey)
		if err != nil {
			return nil, http.StatusInternalServerError, jsonHeader,
				fmt.Errorf("failed to generate JWK thumbprint: %v", err)
		}

		na, err := time.Parse(time.RFC3339, orderPayload.NotAfter)
		if err != nil {
			na = time.Now().Add(time.Hour * 87600) // 10 years from now
		}
		order := &Order{
			Status:          "pending",
			NotAfter:        na,
			ExpiresAt:       time.Now().Add(15 * time.Minute),
			VerifiedDomains: make(map[string]bool),
			Tokens:          []string{},
		}
		var dnsNames []string
		for _, identifier := range orderPayload.Identifiers {
			if identifier.Type == "dns" {
				dnsNames = append(dnsNames, identifier.Value)
				order.VerifiedDomains[identifier.Value] = false
			}
		}
		if len(dnsNames) == 0 {
			return nil, http.StatusBadRequest, jsonHeader, errors.New("no identifiers of dns type")
		}

		id, err := randomID()
		if err != nil {
			return nil, http.StatusInternalServerError, jsonHeader,
				fmt.Errorf("failed to generate random ID: %v", err)
		}

		authorizations := []string{}
		a.challengeStore.Lock()
		defer a.challengeStore.Unlock()

		for _, domain := range dnsNames {
			token, err := randomID()
			if err != nil {
				return nil, http.StatusInternalServerError, jsonHeader,
					fmt.Errorf("failed to generate random ID: %v", err)
			}
			challenge := &Challenge{
				Status:           "pending",
				Token:            token,
				KeyAuthorization: token + "." + thumbprint,
				Domain:           domain,
				ExpiresAt:        time.Now().Add(10 * time.Minute),
			}
			a.challengeStore.challenges[token] = challenge
			order.Tokens = append(order.Tokens, token)
			authorizations = append(authorizations,
				a.baseURL+"/v1/signers/"+name+"/acme/authz?token="+token)
		}

		a.orderStore.Lock()
		defer a.orderStore.Unlock()
		a.orderStore.orders[id] = order

		return toJSON(map[string]any{
			"status":         "pending",
			"authorizations": authorizations,
			"finalize":       a.baseURL + "/v1/signers/" + name + "/acme/finalize?id=" + id,
		}), http.StatusCreated, map[string]string{
			"Location":     a.baseURL + "/v1/signers/" + name + "/acme/order?id=" + id,
			"Content-Type": "application/json",
		}, nil

	case "/orders":
		orders := []string{}
		a.orderStore.Lock()
		for id := range a.orderStore.orders {
			orders = append(orders, a.baseURL+"/v1/signers/"+name+"/acme/order?id="+id)
		}
		a.orderStore.Unlock()
		return toJSON(map[string][]string{
			"orders": orders,
		}), http.StatusOK, jsonHeader, nil

	case "/order":
		id := r.URL.Query().Get("id")
		order := a.getOrder(id)
		if order == nil {
			return nil, http.StatusNotFound, jsonHeader, fmt.Errorf("no order found for id: %s", id)
		}
		a.updateOrderStatus(order)

		authorizations := []string{}
		for _, token := range order.Tokens {
			authorizations = append(authorizations,
				a.baseURL+"/v1/signers/"+name+"/acme/authz?token="+token)
		}

		return toJSON(map[string]any{
			"status":         order.Status,
			"authorizations": authorizations,
			"finalize":       a.baseURL + "/v1/signers/" + name + "/acme/finalize?id=" + id,
		}), http.StatusOK, jsonHeader, nil

	case "/authz":
		token := r.URL.Query().Get("token")
		challenge := a.getChallenge(token)
		if challenge == nil {
			return nil, http.StatusNotFound, jsonHeader,
				fmt.Errorf("no challenge found for token: %s", token)
		}

		return toJSON(map[string]any{
			"status":  challenge.Status, // pending, valid, invalid
			"expires": challenge.ExpiresAt.Format(time.RFC3339),
			"identifier": map[string]string{
				"type":  "dns",
				"value": challenge.Domain,
			},
			"challenges": []map[string]string{{
				"status": challenge.Status,
				"type":   "http-01",
				"url":    a.baseURL + "/v1/signers/" + name + "/acme/challenge?token=" + token,
				"token":  token,
			}},
		}), http.StatusOK, jsonHeader, nil

	case "/challenge":
		token := r.URL.Query().Get("token")
		challenge := a.getChallenge(token)
		if challenge == nil {
			return nil, http.StatusNotFound, jsonHeader,
				fmt.Errorf("no challenge found for token: %s", token)
		}

		status := challenge.Status
		if status == "pending" {
			if time.Now().After(challenge.ExpiresAt) {
				status = "invalid" // challenge expired
			} else {
				url := "http://" + challenge.Domain + "/.well-known/acme-challenge/" + token
				body, err := httpGetWithRetry(r.Context(), url, 10*time.Second, 3, 1*time.Second)
				if err != nil {
					status = "invalid"
				} else {
					if strings.TrimSpace(string(body)) == challenge.KeyAuthorization {
						status = "valid"
					} else {
						status = "invalid"
					}
				}
			}
			a.updateChallenge(challenge, func(c *Challenge) {
				c.Status = status
			})
		}

		return toJSON(map[string]string{
			"status": challenge.Status,
		}), http.StatusOK, jsonHeader, nil

	case "/finalize":
		var finalizePayload struct {
			CSRDerBase64 string `json:"csr"`
		}
		if _, err := a.validateRequest(r, &finalizePayload, true); err != nil {
			return nil, http.StatusBadRequest, jsonHeader, fmt.Errorf("JWS validation failed: %v", err)
		}

		id := r.URL.Query().Get("id")
		order := a.getOrder(id)
		if order == nil {
			return nil, http.StatusNotFound, jsonHeader,
				fmt.Errorf("order not found for id: %s", id)
		}
		if order.Status != "valid" && order.Status != "ready" {
			return nil, http.StatusForbidden, jsonHeader,
				fmt.Errorf("order is neither valid nor ready: %s", id)
		}

		if order.Status == "ready" { // go ahead and try to sign the CSR
			csrDer, err := base64.RawURLEncoding.DecodeString(finalizePayload.CSRDerBase64)
			if err != nil {
				return nil, http.StatusBadRequest, jsonHeader,
					errors.New("failed to base64-decode CSR in payload")
			}
			cr, err := x509.ParseCertificateRequest(csrDer)
			if err != nil {
				return nil, http.StatusBadRequest, jsonHeader, fmt.Errorf("failed to parse CSR: %v", err)
			}

			if len(cr.DNSNames) == 0 {
				return nil, http.StatusBadRequest, jsonHeader,
					errors.New("CSR missing DNS names")
			}
			for _, domain := range cr.DNSNames {
				if !order.VerifiedDomains[domain] {
					return toJSON(map[string]string{
							"status": "invalid",
						}), http.StatusForbidden, jsonHeader,
						fmt.Errorf("challenge not satisfied for domain: %s", domain)
				}
			}
			ttl := time.Until(order.NotAfter)

			// we do not want to issue CA certs via ACME
			signerCfg, err := a.database.GetSignerConfig(r.Context(), name)
			if err != nil {
				return nil, http.StatusInternalServerError, jsonHeader,
					fmt.Errorf("couldn't get signer config: %v", err)
			}

			if signerCfg.IsCA {
				return nil, http.StatusBadRequest, jsonHeader,
					errors.New("cannot issue CA certificates via ACME")
			}

			// load the signer to sign the CSR
			signer, err := a.database.LoadSigner(r.Context(), name)
			if err != nil {
				return nil, http.StatusBadRequest, jsonHeader, fmt.Errorf("couldn't load signer: %v", err)
			}

			// sign the CSR
			cert, fullChain, err := signer.Sign(cr, ttl)
			if err != nil {
				return nil, http.StatusInternalServerError, jsonHeader,
					fmt.Errorf("failed to sign certificate: %v", err)
			}

			eventspkg.OnCertificateSigned(r, a.log, a.database, cert, "ACME")

			var parsed []*x509.Certificate
			for _, certPEM := range fullChain {
				block, _ := pem.Decode([]byte(certPEM))
				if block == nil {
					continue
				}
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					continue
				}
				parsed = append(parsed, cert)
			}

			a.updateOrder(order, func(o *Order) {
				o.Status = "valid"
				o.Cert = parsed
			})
		}

		return toJSON(map[string]string{
			"status":      "valid",
			"certificate": a.baseURL + "/v1/signers/" + name + "/acme/cert?id=" + id,
		}), http.StatusOK, jsonHeader, nil

	case "/cert":
		id := r.URL.Query().Get("id")
		order := a.getOrder(id)
		if order == nil || order.Status != "valid" || len(order.Cert) == 0 {
			return nil, http.StatusNotFound, jsonHeader, errors.New("certificate not ready")
		}
		var out strings.Builder
		for _, cert := range order.Cert {
			pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		}
		return []byte(out.String()), http.StatusOK, map[string]string{
			"Content-Type": "application/pem-certificate-chain",
		}, nil

	default:
		return nil, http.StatusNotFound, jsonHeader,
			errors.New("ACME endpoint not found")
	}
}

func keyID(key *jose.JSONWebKey) string {
	// Generate a consistent key ID from the public key
	keyBytes, _ := key.MarshalJSON()
	hash := sha256.Sum256(keyBytes)
	return base64.RawURLEncoding.EncodeToString(hash[:16])
}

func jwkThumbprint(key *jose.JSONWebKey) (string, error) {
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

// validateJWS reads and validates a JWS-protected request
func (a *Service) validateJWS(r *http.Request, bodyBytes []byte, requireKeyID bool) (*jose.JSONWebKey, []byte, error) {
	// Parse as JWS object directly - v4 API requires signature algorithms
	jws, err := jose.ParseSigned(string(bodyBytes),
		[]jose.SignatureAlgorithm{
			jose.RS256, jose.RS384, jose.RS512,
			jose.ES256, jose.ES384, jose.ES512,
			jose.EdDSA,
		})
	if err != nil {
		return nil, nil, fmt.Errorf("invalid JWS: %v", err)
	}

	// Get the protected header - v4 API uses Signatures slice
	if len(jws.Signatures) == 0 {
		return nil, nil, fmt.Errorf("no JWS signatures")
	}

	header := jws.Signatures[0].Header

	// Validate nonce from extra headers
	if nonce, ok := header.ExtraHeaders["nonce"].(string); ok && nonce != "" {
		if !validateNonce(nonce) {
			return nil, nil, fmt.Errorf("invalid or expired nonce")
		}
	}

	// Validate URL from extra headers
	if url, ok := header.ExtraHeaders["url"].(string); ok && url != "" {
		expectedURL := a.baseURL + r.URL.String()
		if url != expectedURL {
			return nil, nil, fmt.Errorf("URL mismatch, expected %s but got %s", expectedURL, url)
		}
	}

	// Get the verification key
	var publicKey *jose.JSONWebKey

	if header.JSONWebKey != nil {
		if requireKeyID {
			return nil, nil, fmt.Errorf("embedded JWK not allowed for this endpoint")
		}
		publicKey = header.JSONWebKey

	} else if header.KeyID != "" {
		publicKey, err = a.database.GetACMEAccount(header.KeyID)
		if err != nil {
			return nil, nil, fmt.Errorf("unknown key ID: %s", header.KeyID)
		}

	} else {
		return nil, nil, fmt.Errorf("missing both JWK and kid")
	}

	// Verify signature using go-jose v4 API
	payload, err := jws.Verify(publicKey.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("signature verification failed: %v", err)
	}

	return publicKey, payload, nil
}

// validateRequest reads and validates a JWS-protected request,
// unmarshals the payload into structuredPayload if provided and returns the public key
func (a *Service) validateRequest(r *http.Request, structuredPayload any, requiredKeyID bool) (*jose.JSONWebKey, error) {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	// Validate JWS (new account, so no keyID required)
	publicKey, payload, err := a.validateJWS(r, bodyBytes, requiredKeyID)
	if err != nil {
		return nil, fmt.Errorf("JWS validation failed: %v", err)
	}

	if len(payload) > 0 && structuredPayload != nil {
		if err := json.Unmarshal(payload, structuredPayload); err != nil {
			return nil, fmt.Errorf("invalid payload JSON: %v", err)
		}
	}
	return publicKey, nil
}

func httpGetWithRetry(ctx context.Context, url string,
	timeout time.Duration, maxAttempts int, delay time.Duration) ([]byte, error) {
	var lastErr error
	client := &http.Client{
		Timeout: timeout,
	}

	for i := 1; i <= maxAttempts; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}

		resp, err := client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()
			return io.ReadAll(resp.Body)
		}

		if resp != nil {
			resp.Body.Close()
		}
		lastErr = err
		time.Sleep(delay)
	}

	return nil, lastErr
}
