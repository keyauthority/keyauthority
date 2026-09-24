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
	"os"
	"strings"

	authpkg "github.com/keyauthority/keyauthority/internal/auth"
	loggingpkg "github.com/keyauthority/keyauthority/internal/logging"
)

const (
	envCORSOrigin = "CORS_ORIGIN"
)

func (server *Server) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		// w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none';")
		// w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		next.ServeHTTP(w, r)
	})
}

func (server *Server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		allowedOrigin := os.Getenv(envCORSOrigin)
		originOK := origin == allowedOrigin && origin != ""

		pathIgnored := false
		ignoredPaths := []string{"/v1/crl/", "/v1/aia/"}
		for _, p := range ignoredPaths {
			if strings.HasPrefix(r.URL.Path, p) {
				pathIgnored = true
				break
			}
		}

		if originOK && !pathIgnored {
			server.log.Debug(r, "CORS headers set", "origin", origin)
			w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Vary", "Origin")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (server *Server) withAuth(requiredRoles map[string]authpkg.Role, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Determine required role for HTTP method
		requiredRole := authpkg.RoleAny
		if len(requiredRoles) > 0 {
			if role, ok := requiredRoles[r.Method]; ok {
				requiredRole = role
			} else {
				server.logErrorAndWriteHTTP(w, r, http.StatusMethodNotAllowed, "HTTP method not allowed")
				return
			}
		}

		// Verify token
		token, err := authpkg.VerifyToken(r)
		if err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusUnauthorized, "authentication failed", err)
			return
		}
		// Parse immutable claims once, store in context
		tokenInfo := loggingpkg.GetTokenInfoFromClaims(token, true)

		ctx := r.Context()
		ctx = context.WithValue(ctx, loggingpkg.CtxKeyToken{}, token)
		ctx = context.WithValue(ctx, loggingpkg.CtxKeyTokenInfo{}, tokenInfo)
		r = r.WithContext(ctx)

		// Determine environment for RBAC and logging context
		environment, err := server.getEnvironment(r)
		if err != nil {
			server.logErrorAndWriteHTTP(w, r, http.StatusBadRequest, "couldn't determine environment", err)
			return
		}
		if environment != "" {
			ctx = r.Context()
			ctx = context.WithValue(ctx, loggingpkg.CtxKeyEnvironment{}, environment)
			r = r.WithContext(ctx)
		}

		// RBAC check — use roles already extracted above
		if !authpkg.HasRequiredRole(tokenInfo.Roles, environment, requiredRole) {
			server.logErrorAndWriteHTTP(w, r, http.StatusForbidden,
				"insufficient permissions", fmt.Errorf("missing required role: %d", requiredRole))
			return
		}

		server.log.Debug(r, "token verified and required role satisfied")

		// Save logs to DB only after token is verified and RBAC is checked
		ctx = r.Context()
		ctx = context.WithValue(ctx, loggingpkg.CtxKeyWriteLogToDB{}, true)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}
