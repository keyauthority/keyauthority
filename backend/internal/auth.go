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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
)

type Role uint64

const (
	envKeycloakURL                  = "KEYCLOAK_URL"
	envKeycloakRealm                = "KEYCLOAK_REALM"
	envKeycloakExchangeClientID     = "KEYCLOAK_EXCHANGE_CLIENT_ID"
	envKeycloakExchangeClientSecret = "KEYCLOAK_EXCHANGE_CLIENT_SECRET"

	RoleAny      Role = 0       // No roles
	RoleOperator Role = 1 << 0  // bit 0 set
	RoleAuditor  Role = 1 << 15 // bit 15 set
	RoleApprover Role = 1 << 30 // bit 30 set
	//RoleAdmin      uint64 = (1 << 60) - 1 // 1...1111 (60 bits set to 1)
)

var (
	authenticatorOnce      sync.Once
	kcURL                  string
	kcRealm                string
	kcExchangeClientID     string
	kcExchangeClientSecret string
	kcIssuer               string

	roleMap map[string]Role = map[string]Role{
		"KEYAUTHORITY_OPERATOR":   RoleOperator,
		"KEYAUTHORITY_AUDITOR":    RoleAuditor,
		"KEYAUTHORITY_APPROVER":   RoleApprover,
		"KEYAUTHORITY_AUTHORIZER": RoleApprover, // for backward compatibility
	}
)

type TokenRequest struct {
	// Username and RoleID are treated as the same
	Username string `json:"username,omitempty"`
	RoleID   string `json:"role_id,omitempty"`
	// Password and SecretID are treated as the same
	Password string `json:"password,omitempty"`
	SecretID string `json:"secret_id,omitempty"`

	// JWT used for JWT/OIDC auth method
	Jwt string `json:"jwt,omitempty"`
}

func SetupAuthenticator() {
	authenticatorOnce.Do(func() {
		kcURL = os.Getenv(envKeycloakURL)
		kcRealm = os.Getenv(envKeycloakRealm)
		kcExchangeClientID = os.Getenv(envKeycloakExchangeClientID)
		kcExchangeClientSecret = os.Getenv(envKeycloakExchangeClientSecret)
		kcIssuer = fmt.Sprintf("%s/realms/%s", kcURL, kcRealm)
	})
}

func ExchangeForToken(reqBody *TokenRequest) (string, error) {
	values := url.Values{}

	username := reqBody.Username
	if username == "" {
		username = reqBody.RoleID
	}
	password := reqBody.Password
	if password == "" {
		password = reqBody.SecretID
	}

	values.Set("client_id", kcExchangeClientID)

	if kcExchangeClientSecret != "" {
		values.Set("client_secret", kcExchangeClientSecret)
	}
	if username != "" {
		values.Set("username", username)
	}
	if password != "" {
		values.Set("password", password)
	}
	if reqBody.Jwt != "" {
		values.Set("assertion", reqBody.Jwt)
	}

	if username != "" && password != "" {
		values.Set("grant_type", "password")
	} else if reqBody.Jwt != "" {
		values.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	}

	r, err := http.Post(kcIssuer+"/protocol/openid-connect/token",
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

func GetTokenFromHeaders(r *http.Request) (string, error) {
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	vaultToken := strings.TrimSpace(r.Header.Get("X-Vault-Token"))

	if authHeader == "" && vaultToken == "" {
		return "", fmt.Errorf("missing Authorization header or X-Vault-Token header")
	}

	token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	if token == "" {
		token = vaultToken
	}
	if token == "" {
		return "", fmt.Errorf("empty token in Authorization/X-Vault-Token headers")
	}
	return token, nil
}

func VerifyToken(r *http.Request) (*oidc.IDToken, error) {
	tokenStr, err := GetTokenFromHeaders(r)
	if err != nil {
		return nil, err
	}

	provider, err := oidc.NewProvider(r.Context(), kcIssuer)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	verifier := provider.Verifier(&oidc.Config{
		// ClientID:          internalClient.ClientID,
		SkipClientIDCheck: true, // set true if using public clients without enforcing audience
	})

	idToken, err := verifier.Verify(r.Context(), tokenStr)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	return idToken, nil
}

func HasRequiredRole(roles []string, environment string, requiredRole Role) bool {
	if requiredRole == RoleAny {
		return true
	}
	roleVal := RoleAny
	for _, r := range roles {
		if rv, ok := roleMap[r]; ok {
			roleVal |= rv
		} else if after, ok := strings.CutSuffix(r, "_"+environment); ok {
			if rv, ok1 := roleMap[after]; ok1 {
				roleVal |= rv
			}
		}
	}
	return (roleVal & requiredRole) == requiredRole
}

func InsecureClaims(token string, claims any) {
	splitToken := strings.Split(token, ".")
	if len(splitToken) != 3 {
		return
	}

	payload, err := url.QueryUnescape(splitToken[1])
	if err != nil {
		return
	}

	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return
	}

	json.Unmarshal(decoded, claims)
}
