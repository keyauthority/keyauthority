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
	"net/http"
	"net/url"

	databasepkg "github.com/keyauthority/keyauthority/internal/database"
)

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
