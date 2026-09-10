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
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	loggingpkg "github.com/keyauthority/keyauthority/internal/logging"
)

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
