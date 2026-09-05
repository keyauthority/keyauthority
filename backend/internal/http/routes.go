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

	authpkg "github.com/keyauthority/keyauthority/internal/auth"
	metricspkg "github.com/keyauthority/keyauthority/internal/metrics"
	"github.com/keyauthority/keyauthority/swagger"
)

func (server *Server) SetHandlers() {
	server.registerKeyRoutes()
	server.registerSignerRoutes()
	server.registerSecretRoutes()
	server.registerCertificateRoutes()
	server.registerPendingRequestRoutes()
	server.registerMiscRoutes()
	server.registerVaultCompatibilityRoutes()
	server.registerSwaggerRoutes()
}

func (server *Server) registerKeyRoutes() {
	server.handler.Handle("/v1/keys", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet:  authpkg.RoleAny,      // get keys
			http.MethodPost: authpkg.RoleOperator, // create key
		},
		server.keysHandler()))

	server.handler.Handle("/v1/keys/{id}", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet:    authpkg.RoleOperator, // get key
			http.MethodDelete: authpkg.RoleOperator, // delete key
		},
		server.keyHandler()))

	server.handler.Handle("/v1/keys/{id}/ready", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleOperator, // get key readiness
		},
		server.keyReadinessHandler()))
}

func (server *Server) registerSignerRoutes() {
	server.handler.Handle("/v1/signers", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleAny, // get signers
		},
		server.signersHandler()))

	server.handler.Handle("/v1/signers/{name}", server.withAuth(
		map[string]authpkg.Role{
			http.MethodPost:   authpkg.RoleOperator, // create signer
			http.MethodDelete: authpkg.RoleOperator, // delete signer
		},
		server.signerHandler()))

	server.handler.Handle("/v1/signers/{name}/private-key", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleOperator, // get private key ID
		},
		server.signerPrivateKeyHandler()))

	server.handler.Handle("/v1/signers/{name}/config", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleOperator, // get signer config
			http.MethodPut: authpkg.RoleOperator, // update signer config
		},
		server.signerConfigHandler()))

	server.handler.Handle("/v1/signers/{name}/ca-chain", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleOperator, // get CA chain
			http.MethodPut: authpkg.RoleOperator, // update CA chain
		},
		server.signerCAChainHandler()))

	server.handler.Handle("/v1/signers/{name}/ca-csr", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleOperator, // create CA CSR
		},
		server.signerCSRHandler()))

	server.handler.Handle("/v1/signers/{name}/sign",
		metricspkg.WithHttpMetrics("/v1/signers/{name}/sign", server.withAuth(
			map[string]authpkg.Role{
				http.MethodPost: authpkg.RoleOperator, // sign certificate
			},
			server.signerSignHandler())))

	server.handler.Handle("/v1/signers/{name}/revoke",
		metricspkg.WithHttpMetrics("/v1/signers/{name}/revoke", server.withAuth(
			map[string]authpkg.Role{
				http.MethodPost: authpkg.RoleOperator, // revoke certificate
			},
			server.signerRevokeHandler())))

	server.nonTLSHandler.Handle("/v1/crl/{hashOfSignerName:.*}", server.signerCRLHandler())
	server.nonTLSHandler.Handle("/v1/aia/{hashOfSignerName:.*}", server.signerAIAHandler())

	// Leave this here until the ACME-specific refactor.
	server.handler.PathPrefix("/v1/signers/{name}/acme").Handler(server.signerACMEHandler())
}

func (server *Server) registerSecretRoutes() {
	server.handler.Handle("/v1/secrets", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleAny, // get secrets
		},
		server.secretsHandler()))

	server.handler.Handle("/v1/secrets/data/{name:.+}",
		metricspkg.WithHttpMetrics("/v1/secrets/data/{name}", server.withAuth(
			map[string]authpkg.Role{
				http.MethodGet: authpkg.RoleOperator, // get secret (Hashicorp Vault compatible)
			},
			server.secretHandler())))

	server.handler.Handle("/v1/secrets/{name:.+}",
		metricspkg.WithHttpMetrics("/v1/secrets/{name}", server.withAuth(
			map[string]authpkg.Role{
				http.MethodGet:    authpkg.RoleOperator, // get secret
				http.MethodPut:    authpkg.RoleOperator, // insert secret
				http.MethodPost:   authpkg.RoleOperator, // update secret
				http.MethodPatch:  authpkg.RoleOperator, // patch secret
				http.MethodDelete: authpkg.RoleOperator, // delete secret
			},
			server.secretHandler())))
}

func (server *Server) registerCertificateRoutes() {
	server.handler.Handle("/v1/certs", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleAny, // get certs
		},
		server.certsHandler()))

	server.handler.Handle("/v1/certs/{serial}/pem", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleAny, // get cert PEM
		},
		server.certHandler()))
}

func (server *Server) registerPendingRequestRoutes() {
	server.handler.Handle("/v1/pending-requests", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleApprover, // get pending requests
		},
		server.pendingRequestsHandler()))

	server.handler.Handle("/v1/pending-requests/{id}",
		metricspkg.WithHttpMetrics("/v1/pending-requests/{id}", server.withAuth(
			map[string]authpkg.Role{
				http.MethodPost:   authpkg.RoleApprover, // approve pending request
				http.MethodDelete: authpkg.RoleApprover, // reject pending request
			},
			server.pendingRequestHandler())))

	server.handler.Handle("/v1/pending-requests/{id}/body", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleApprover, // get pending request body
		},
		server.pendingRequestBodyHandler()))
}

func (server *Server) registerMiscRoutes() {
	server.handler.Handle("/v1/dashboard", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleAny,
		},
		server.dashboardHandler()))

	server.handler.Handle("/v1/logs", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleAuditor, // get logs
		},
		server.logsHandler()))

	server.handler.Handle("/v1/token", server.tokenHandler())

	server.handler.Handle("/v1/health", server.healthHandler())

	server.handler.Handle("/v1/oidc/jwks/kubernetes", server.kubernetesJWKSHandler())
}

func (server *Server) registerVaultCompatibilityRoutes() {
	server.handler.Handle("/v1/auth/{mount}/login", server.tokenHandler())

	server.handler.Handle("/v1/sys/health", server.healthHandler())

	server.handler.PathPrefix("/v1/sys/internal/ui/mounts/").Handler(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSONOk(w, map[string]any{
				"type": "kv",
				"path": "secrets/",
				"options": map[string]any{
					"version": "2",
				},
			})
		}))
}

func (server *Server) registerSwaggerRoutes() {
	server.handler.PathPrefix("/swagger/").Handler(
		http.StripPrefix("/swagger/", http.FileServer(http.FS(swagger.Files))))
}
