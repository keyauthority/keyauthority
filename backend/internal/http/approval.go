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
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	loggingpkg "github.com/keyauthority/keyauthority/internal/logging"
)

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
