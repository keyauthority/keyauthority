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

package internal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	cachepkg "github.com/keyauthority/keyauthority/internal/cache"
	loggingpkg "github.com/keyauthority/keyauthority/internal/logging"
)

type Role uint64

type tokenCacheData struct {
	providerIdx int
	verifier    *oidc.IDTokenVerifier
}

const (
	envKeycloakURL                   = "KEYCLOAK_URL"
	envKeycloakRealm                 = "KEYCLOAK_REALM"
	envKeycloakDiscoveryClientID     = "KEYCLOAK_DISCOVERY_CLIENT_ID"
	envKeycloakDiscoveryClientSecret = "KEYCLOAK_DISCOVERY_CLIENT_SECRET"

	RoleAny      Role = 0       // No roles
	RoleOperator Role = 1 << 0  // bit 0 set
	RoleAuditor  Role = 1 << 15 // bit 15 set
	RoleApprover Role = 1 << 30 // bit 30 set
	//RoleAdmin      uint64 = (1 << 60) - 1 // 1...1111 (60 bits set to 1)
)

var (
	// Map of OIDC issuer URLs to file paths containing tokens for authenticated discovery
	authForOIDCDiscovery = map[string]string{
		"https://kubernetes.default.svc":               "/var/run/secrets/kubernetes.io/serviceaccount/token",
		"https://kubernetes.default.svc.cluster.local": "/var/run/secrets/kubernetes.io/serviceaccount/token",
	}

	// HTTP clients with tokens for OIDC discovery, depends on authForOIDCDiscovery map above
	httpClientsWithTokens = make(map[string]*http.Client)

	RoleMap map[string]Role = map[string]Role{
		"KEYAUTHORITY_OPERATOR":   RoleOperator,
		"KEYAUTHORITY_AUDITOR":    RoleAuditor,
		"KEYAUTHORITY_APPROVER":   RoleApprover,
		"KEYAUTHORITY_AUTHORIZER": RoleApprover, // for backward compatibility
	}

	// cache tokenHash -> tokenCacheData
	tokenCache = cachepkg.NewCache()
)

type TokenRequest struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`

	// Hashicorp Vault specific
	// JWT used for JWT/OIDC auth method
	Jwt string `json:"jwt,omitempty"`
	// Username and RoleID are treated as the same
	RoleID string `json:"role_id,omitempty"`
	// Password and SecretID are treated as the same
	SecretID string `json:"secret_id,omitempty"`
}

type clientSummary struct {
	ID       string `json:"id"`
	ClientID string `json:"clientID"` // used only for filtering keyauthority- clients
}

type clientDetail struct {
	ClientID         string            `json:"clientID"`
	VerificationOpts string            `json:"description"` // used to store verification options as JSON string
	AuthType         string            `json:"clientAuthenticatorType"`
	Secret           string            `json:"secret"`
	Attributes       map[string]string `json:"attributes"`
}

type verificationOps struct {
	SkipIssuerCheck bool           `json:"skipIssuerCheck"`
	RequiredClaims  map[string]any `json:"requiredClaims,omitempty"`
}

type provider struct {
	// clientID
	ClientID string `json:"clientID,omitempty"`
	// OIDC provider
	Provider *oidc.Provider `json:"-"`
	// Issuer URL
	Issuer string `json:"issuer"`
	// Required claims for tokens
	VerificationOpts verificationOps `json:"verificationOpts"`
	// Override roles for tokens from this provider
	OverrideRoles []string `json:"overrideRoles,omitempty"`
}

type Authenticator struct {
	// Keycloak clients info, used for token requests only
	Clients []*clientDetail
	// All configured OIDC providers, first one is always the internal provider
	Providers []*provider
}

func NewAuthenticator(ctx context.Context) (*Authenticator, []*loggingpkg.LogEntry, error) {
	// clear token cache
	tokenCache.Clear()

	// prepare HTTP clients with tokens for OIDC discovery, if any
	logEntries := createHttpClientsWithTokens()

	// --- Configure internal provider
	internalProviderURL := fmt.Sprintf("%s/realms/%s",
		os.Getenv(envKeycloakURL),
		os.Getenv(envKeycloakRealm),
	)
	internalProv, err := oidc.NewProvider(
		oidc.ClientContext(ctx, getHttpClientForIssuer(internalProviderURL)),
		internalProviderURL)

	if err != nil {
		return nil, logEntries, err
	}
	issuerURI, err := url.Parse(internalProviderURL)
	if err != nil {
		return nil, logEntries, err
	}

	// skip issuer check for keycloak running on HTTP localhost
	skipIssuerCheck := issuerURI.Scheme == "http" &&
		(issuerURI.Host == "127.0.0.1" ||
			issuerURI.Host == "localhost" ||
			issuerURI.Host == "host.docker.internal" ||
			strings.HasPrefix(issuerURI.Host, "127.0.0.1:") ||
			strings.HasPrefix(issuerURI.Host, "localhost:") ||
			strings.HasPrefix(issuerURI.Host, "host.docker.internal:"))

	if skipIssuerCheck {
		logEntries = append(logEntries, &loggingpkg.LogEntry{
			Level:   slog.LevelDebug,
			Message: "skipping issuer check for internal provider due to HTTP localhost",
		})
	}

	internalProvider := &provider{
		Issuer: internalProviderURL,
		VerificationOpts: verificationOps{
			SkipIssuerCheck: skipIssuerCheck,
		},
		Provider: internalProv,
	}

	logEntries = append(logEntries, &loggingpkg.LogEntry{
		Level:   slog.LevelInfo,
		Message: "internal OIDC provider configured",
		Args: []any{
			slog.String("issuer", internalProviderURL),
		},
	})

	// --- Discover and configure external providers
	var externalProviders []*provider
	clients := []*clientDetail{}
	discoveryToken, err := getDiscoveryToken()
	if err != nil {
		logEntries = append(logEntries, &loggingpkg.LogEntry{
			Level:   slog.LevelWarn,
			Message: "couldn't obtain token for client discovery",
			Args:    []any{slog.Any("error", err)},
		})

	} else {
		clientSummaries, err := getAllClientSummaries(discoveryToken)
		if err != nil {
			logEntries = append(logEntries, &loggingpkg.LogEntry{
				Level:   slog.LevelWarn,
				Message: "couldn't discover clients",
				Args:    []any{slog.Any("error", err)},
			})

		} else {
			for _, summary := range clientSummaries {
				if summary.ClientID == os.Getenv(envKeycloakDiscoveryClientID) {
					logEntries = append(logEntries, &loggingpkg.LogEntry{
						Level:   slog.LevelDebug,
						Message: "skipping client for external OIDC provider discovery",
						Args: []any{
							slog.String("clientID", summary.ClientID),
							slog.Any("reason", "this client is used for discovery only"),
						},
					})
					continue
				}

				if !strings.HasPrefix(summary.ClientID, "keyauthority-") {
					logEntries = append(logEntries, &loggingpkg.LogEntry{
						Level:   slog.LevelDebug,
						Message: "skipping client for external OIDC provider discovery",
						Args: []any{
							slog.String("clientID", summary.ClientID),
							slog.Any("reason", "client ID must start with 'keyauthority-'"),
						},
					})
					continue
				}

				client, err := getClientDetails(discoveryToken, summary.ID)
				if err != nil {
					logEntries = append(logEntries, &loggingpkg.LogEntry{
						Level:   slog.LevelWarn,
						Message: "skipping client for external OIDC provider discovery",
						Args: []any{
							slog.String("clientID", summary.ClientID),
							slog.Any("reason", err),
						},
					})
					continue
				}

				clients = append(clients, client)

				if client.AuthType != "client-jwt" {
					logEntries = append(logEntries, &loggingpkg.LogEntry{
						Level:   slog.LevelDebug,
						Message: "skipping client for external OIDC provider discovery",
						Args: []any{
							slog.String("clientID", summary.ClientID),
							slog.Any("reason", "unsupported authenticator type: "+client.AuthType),
						},
					})
					continue
				}

				externalProvider, err := newProvider(ctx, client)
				if err != nil {
					logEntries = append(logEntries, &loggingpkg.LogEntry{
						Level:   slog.LevelWarn,
						Message: "skipping client for external OIDC provider discovery",
						Args: []any{
							slog.String("clientID", summary.ClientID),
							slog.Any("reason", err),
						},
					})
					continue
				}

				if allRoles, err := getClientRoles(discoveryToken, summary.ID); err == nil {
					for _, role := range allRoles {
						if strings.HasPrefix(role, "KEYAUTHORITY_") {
							externalProvider.OverrideRoles = append(externalProvider.OverrideRoles, role)
						}
					}
				}

				externalProviders = append(externalProviders, externalProvider)
				logEntries = append(logEntries, &loggingpkg.LogEntry{
					Level:   slog.LevelInfo,
					Message: "external OIDC provider configured",
					Args: []any{
						slog.String("clientID", summary.ClientID),
						slog.String("issuer", externalProvider.Issuer),
						slog.Any("roles", externalProvider.OverrideRoles),
					},
				})
			}
		}
	}

	return &Authenticator{
		Clients:   clients,
		Providers: append([]*provider{internalProvider}, externalProviders...),
	}, logEntries, nil
}

func (a *Authenticator) ExchangeForToken(reqBody *TokenRequest) (string, error) {
	// if JWT is provided in the request body, just send it back
	if reqBody.Jwt != "" {
		return reqBody.Jwt, nil
	}
	// otherwise, try to exchange for a token using the configured clients
	for _, client := range a.Clients {
		if token, err := a.exchangeForToken(client, reqBody); err == nil {
			return token, nil
		}
	}
	return "", fmt.Errorf("no client could exchange request for token")
}

func (a *Authenticator) exchangeForToken(client *clientDetail, reqBody *TokenRequest) (string, error) {
	values := url.Values{}
	switch client.AuthType {
	case "client-secret":
		username := reqBody.Username
		if username == "" {
			username = reqBody.RoleID
		}
		password := reqBody.Password
		if password == "" {
			password = reqBody.SecretID
		}

		values.Set("grant_type", "password")
		values.Set("client_id", client.ClientID)
		values.Set("client_secret", client.Secret)
		values.Set("username", username)
		values.Set("password", password)

	case "client-jwt":
		// values.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
		// values.Set("client_id", client.ClientID)
		// values.Set("subject_token", reqBody.Jwt)
		return reqBody.Jwt, nil

	default:
		return "", errors.New("unsupported authenticator type")
	}

	r, err := http.Post(a.Providers[0].Issuer+"/protocol/openid-connect/token",
		"application/x-www-form-urlencoded",
		bytes.NewBufferString(values.Encode()),
	)

	if err != nil {
		return "", err
	}
	defer r.Body.Close()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}

	var resp struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("unmarshal response: %w", err)
	}
	if resp.Error != "" {
		return "", errors.New(resp.Error)
	}

	return resp.AccessToken, nil
}

func (a *Authenticator) VerifyToken(r *http.Request) (*oidc.IDToken, []*loggingpkg.LogEntry, []string, error) {
	authHeader := r.Header.Get("Authorization")
	vaultToken := r.Header.Get("X-Vault-Token")
	if authHeader == "" && vaultToken == "" {
		return nil, []*loggingpkg.LogEntry{}, nil, fmt.Errorf("missing Authorization header or X-Vault-Token header")
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenStr == "" {
		tokenStr = vaultToken
	}

	idToken, providerIDx, logEntries := a.verifyOIDCToken(r.Context(), tokenStr)
	if providerIDx == -1 {
		return nil, logEntries, nil, fmt.Errorf("invalid token")
	}
	return idToken, logEntries, a.Providers[providerIDx].OverrideRoles, nil
}

func (a *Authenticator) HasRequiredRole(roles []string, environment string, requiredRole Role) bool {
	if requiredRole == RoleAny {
		return true
	}
	roleVal := RoleAny
	for _, r := range roles {
		if rv, ok := RoleMap[r]; ok {
			roleVal |= rv
		} else if after, ok := strings.CutSuffix(r, "_"+environment); ok {
			if rv, ok1 := RoleMap[after]; ok1 {
				roleVal |= rv
			}
		}
	}
	return (roleVal & requiredRole) == requiredRole
}

//------ Helpers ------//

func newProvider(ctx context.Context, client *clientDetail) (*provider, error) {
	var vOpts verificationOps
	if client.VerificationOpts != "" {
		if err := json.Unmarshal([]byte(client.VerificationOpts), &vOpts); err != nil {
			return nil, err
		}
	}

	issuer := ""
	httpClient := http.DefaultClient

	if jwksURL, ok := client.Attributes["jwks.url"]; ok {
		var err error
		issuer, err = extractIssuerFromJWKSURL(jwksURL)
		if err != nil {
			return nil, err
		}
		httpClient = getHttpClientForIssuer(issuer)

	} else if jwks, ok := client.Attributes["jwks.string"]; ok && jwks != "" {
		issuer = "https://" + client.ClientID + ".keyauthority.net"
		vOpts.SkipIssuerCheck = true // must skip issuer check when using static JWKS
		// custom HTTP client that serves static JWKS
		httpClient = &http.Client{
			Transport: &staticJWKSTransport{
				jwksJSON: []byte(jwks),
				issuer:   issuer,
			},
		}
	}

	p, err := oidc.NewProvider(oidc.ClientContext(ctx, httpClient), issuer)
	if err != nil {
		return nil, err
	}

	return &provider{
		ClientID:         client.ClientID,
		Provider:         p,
		Issuer:           issuer,
		VerificationOpts: vOpts,
	}, nil
}

func getDiscoveryToken() (string, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", os.Getenv(envKeycloakDiscoveryClientID))
	data.Set("client_secret", os.Getenv(envKeycloakDiscoveryClientSecret))

	resp, err := http.PostForm(
		fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token",
			os.Getenv(envKeycloakURL),
			os.Getenv(envKeycloakRealm)), data)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token request failed: %s", string(body))
	}

	var tokenRes struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenRes); err != nil {
		return "", err
	}
	return tokenRes.AccessToken, nil
}

func getAllClientSummaries(discoveryToken string) ([]*clientSummary, error) {
	req, _ := http.NewRequest("GET",
		fmt.Sprintf("%s/admin/realms/%s/clients",
			os.Getenv(envKeycloakURL),
			os.Getenv(envKeycloakRealm)), nil)
	req.Header.Set("Authorization", "Bearer "+discoveryToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get clients failed: %s", string(body))
	}

	var clients []*clientSummary
	if err := json.NewDecoder(resp.Body).Decode(&clients); err != nil {
		return nil, err
	}
	// sort clients by ClientID
	sort.Slice(clients, func(i, j int) bool {
		return clients[i].ClientID < clients[j].ClientID
	})

	return clients, nil
}

func getClientDetails(token, clientID string) (*clientDetail, error) {
	url := fmt.Sprintf("%s/admin/realms/%s/clients/%s",
		os.Getenv(envKeycloakURL),
		os.Getenv(envKeycloakRealm),
		clientID)
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, errors.New("get client detail failed: " + string(body))
	}

	var detail clientDetail
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		return nil, err
	}
	return &detail, nil
}

func getClientRoles(token, clientID string) ([]string, error) {
	url := fmt.Sprintf("%s/admin/realms/%s/clients/%s/roles",
		os.Getenv(envKeycloakURL), os.Getenv(envKeycloakRealm), clientID)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get roles failed: %s", string(body))
	}

	var roles []struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&roles); err != nil {
		return nil, err
	}

	names := make([]string, len(roles))
	for i, r := range roles {
		names[i] = r.Name
	}
	return names, nil
}

func getHttpClientForIssuer(issuer string) *http.Client {
	if client, ok := httpClientsWithTokens[issuer]; ok {
		return client
	}
	return http.DefaultClient
}

// verifyOIDCToken tries to verify the token against all configured OIDC providers.
// It returns the verified ID token and the index of the provider that verified it successfully.
// If no provider could verify the token, it returns nil and -1.
// IMPORTANT: caller must compare the returned index against -1 to check for verification failure.
func (a *Authenticator) verifyOIDCToken(ctx context.Context, token string) (*oidc.IDToken, int, []*loggingpkg.LogEntry) {
	// check cache first
	hashOfTokenBytes := sha256.Sum256([]byte(token))
	hashOfToken := fmt.Sprintf("%x", hashOfTokenBytes[:])
	if tcd, ok := tokenCache.Get(hashOfToken); ok {
		cacheData := tcd.(tokenCacheData)
		idToken, err := cacheData.verifier.Verify(ctx, token)
		if err != nil {
			return nil, -1, []*loggingpkg.LogEntry{{
				Level:   slog.LevelDebug,
				Message: "token verification failed for cached verifier",
				Args: []any{
					slog.Any("issuer", a.Providers[cacheData.providerIdx].Issuer),
					slog.Any("error", err),
				},
			}}
		}
		return idToken, cacheData.providerIdx, []*loggingpkg.LogEntry{{
			Level:   slog.LevelDebug,
			Message: "token verified successfully with cached verifier",
			Args: []any{
				slog.Any("issuer", a.Providers[cacheData.providerIdx].Issuer),
			},
		}}
	}

	var logEntries []*loggingpkg.LogEntry
	for i, provider := range a.Providers {
		verifier := provider.Provider.Verifier(&oidc.Config{
			// ClientID:          internalClient.ClientID,
			SkipClientIDCheck: true, // set true if using public clients without enforcing audience
			SkipIssuerCheck:   provider.VerificationOpts.SkipIssuerCheck,
		})

		idToken, err := verifier.Verify(ctx, token)
		if err != nil {
			logEntries = append(logEntries, &loggingpkg.LogEntry{
				Level:   slog.LevelDebug,
				Message: "token verification failed",
				Args: []any{
					slog.String("issuer", provider.Issuer),
					slog.Any("error", err),
				},
			})
			continue
		}

		// let's verify the tokenRequirements if any
		if provider.VerificationOpts.RequiredClaims != nil {
			var claims map[string]any
			if err := idToken.Claims(&claims); err != nil {
				logEntries = append(logEntries, &loggingpkg.LogEntry{
					Level:   slog.LevelDebug,
					Message: "token has a valid signature but couldn't extract claims from it",
					Args: []any{
						slog.String("issuer", provider.Issuer),
						slog.Any("error", err),
					},
				})
				continue
			}

			if !DeepIncluded(claims, provider.VerificationOpts.RequiredClaims) {
				logEntries = append(logEntries, &loggingpkg.LogEntry{
					Level:   slog.LevelDebug,
					Message: "token has a valid signature but claims do not satisfy requirements",
					Args: []any{
						slog.String("issuer", provider.Issuer),
						slog.Any("requiredClaims", provider.VerificationOpts.RequiredClaims),
						slog.Any("tokenClaims", claims),
					},
				})
				continue
			}
		}

		// cache the successful verifier for future tokens with the same hash
		tokenCache.SetWithTTL(hashOfToken, tokenCacheData{
			providerIdx: i,
			verifier:    verifier,
		}, time.Until(idToken.Expiry))

		// token is valid for this provider
		return idToken, i, []*loggingpkg.LogEntry{{
			Level:   slog.LevelDebug,
			Message: "token verified successfully",
			Args: []any{
				slog.String("issuer", provider.Issuer),
			},
		}}
	}

	return nil, -1, logEntries
}

func createHttpClientsWithTokens() []*loggingpkg.LogEntry {
	var warnings []*loggingpkg.LogEntry
	for issuer, tokenPath := range authForOIDCDiscovery {
		tokenBytes, err := os.ReadFile(tokenPath)
		if err != nil {
			warnings = append(warnings, &loggingpkg.LogEntry{
				Level:   slog.LevelWarn,
				Message: "couldn't read bearer token for OIDC discovery",
				Args:    []any{slog.Any("error", err)},
			})
			continue
		}
		httpClientsWithTokens[issuer] = &http.Client{
			Timeout: 10 * time.Second,
			Transport: &tokenInjectorTransport{
				token: string(tokenBytes),
			},
		}
	}
	return warnings
}

func extractIssuerFromJWKSURL(jwksURL string) (string, error) {
	parsedURL, err := url.Parse(jwksURL)
	if err != nil {
		return "", fmt.Errorf("couldn't parse JWKS URL: %w", err)
	}

	idx := strings.Index(parsedURL.Path, "/.well-known/")
	if idx == -1 {
		idx = len(parsedURL.Path)
	}
	return parsedURL.Scheme + "://" + parsedURL.Host + parsedURL.Path[:idx], nil
}

type tokenInjectorTransport struct {
	token string
}

func (t *tokenInjectorTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+t.token)
	return http.DefaultTransport.RoundTrip(req)
}

type staticJWKSTransport struct {
	jwksJSON []byte
	issuer   string
}

func (t *staticJWKSTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasSuffix(req.URL.Path, "/.well-known/openid-configuration") {
		// Return OIDC discovery document
		type config struct {
			Issuer         string   `json:"issuer"`
			JwksURI        string   `json:"jwks_uri"`
			SupportedAlgos []string `json:"id_token_signing_alg_values_supported"`
		}
		b, _ := json.Marshal(&config{
			Issuer:         t.issuer,
			JwksURI:        t.issuer + "/jwks",
			SupportedAlgos: []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"},
		})
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(b)),
		}, nil
	}

	if strings.HasSuffix(req.URL.Path, "/jwks") {
		// Return static JWKS
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(t.jwksJSON)),
		}, nil
	}

	return http.DefaultTransport.RoundTrip(req)
}

func DeepIncluded(a, b any) bool {
	return deepIncluded(reflect.ValueOf(a), reflect.ValueOf(b))
}

func deepIncluded(a, b reflect.Value) bool {
	// unwrap interfaces
	for a.Kind() == reflect.Interface {
		a = a.Elem()
	}
	for b.Kind() == reflect.Interface {
		b = b.Elem()
	}

	// nil cases
	if !b.IsValid() {
		return true // empty subset
	}
	if !a.IsValid() {
		return false // b nonempty, a empty ⇒ cannot match
	}

	// exact type match required for primitives
	if isPrimitive(a) && isPrimitive(b) {
		return reflect.DeepEqual(a.Interface(), b.Interface())
	}

	switch b.Kind() {

	case reflect.Map:
		if a.Kind() != reflect.Map {
			return false
		}
		for _, key := range b.MapKeys() {
			av := a.MapIndex(key)
			if !av.IsValid() {
				return false
			}
			if !deepIncluded(av, b.MapIndex(key)) {
				return false
			}
		}
		return true

	case reflect.Slice, reflect.Array:
		if a.Kind() != b.Kind() {
			return false
		}
		if b.Len() > a.Len() {
			return false
		}
		for i := 0; i < b.Len(); i++ {
			if !deepIncluded(a.Index(i), b.Index(i)) {
				return false
			}
		}
		return true

	case reflect.Struct:
		if a.Kind() != reflect.Struct {
			return false
		}
		for i := 0; i < b.NumField(); i++ {
			bf := b.Field(i)
			af := a.Field(i)
			if af.CanInterface() && bf.CanInterface() {
				if !deepIncluded(af, bf) {
					return false
				}
			}
		}
		return true
	}

	// fallback: require exact equality
	return reflect.DeepEqual(a.Interface(), b.Interface())
}

func isPrimitive(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64,
		reflect.String:
		return true
	}
	return false
}
