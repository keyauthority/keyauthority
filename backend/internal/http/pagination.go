// Copyright 2025 KeyAuthority.

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
