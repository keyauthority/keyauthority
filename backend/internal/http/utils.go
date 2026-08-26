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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	loggingpkg "github.com/keyauthority/keyauthority/internal/logging"
)

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
