// Copyright 2025 KeyAuthority.

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
		http.HandlerFunc(server.handleGetKeysOrCreateKey)))

	server.handler.Handle("/v1/keys/{id}", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet:    authpkg.RoleOperator, // get key
			http.MethodDelete: authpkg.RoleOperator, // delete key
		},
		http.HandlerFunc(server.handleGetKey)))

	server.handler.Handle("/v1/keys/{id}/ready", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleOperator, // get key readiness
		},
		http.HandlerFunc(server.handleGetKeyReadiness)))
}

func (server *Server) registerSignerRoutes() {
	server.handler.Handle("/v1/signers", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleAny, // get signers
		},
		http.HandlerFunc(server.handleGetSigners)))

	server.handler.Handle("/v1/signers/{name}", server.withAuth(
		map[string]authpkg.Role{
			http.MethodPost:   authpkg.RoleOperator, // create signer
			http.MethodDelete: authpkg.RoleOperator, // delete signer
		},
		http.HandlerFunc(server.handleCreateOrDeleteSigner)))

	server.handler.Handle("/v1/signers/{name}/private-key", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleOperator, // get private key ID
		},
		http.HandlerFunc(server.handleGetSignerPrivateKeyID)))

	server.handler.Handle("/v1/signers/{name}/config", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleOperator, // get signer config
			http.MethodPut: authpkg.RoleOperator, // update signer config
		},
		http.HandlerFunc(server.handleGetOrUpdateSignerConfig)))

	server.handler.Handle("/v1/signers/{name}/ca-chain", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleOperator, // get CA chain
			http.MethodPut: authpkg.RoleOperator, // update CA chain
		},
		http.HandlerFunc(server.handleGetOrUpdateSignerCAChain)))

	server.handler.Handle("/v1/signers/{name}/ca-csr", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleOperator, // create CA CSR
		},
		http.HandlerFunc(server.handleCreateSignerCARequest)))

	server.handler.Handle("/v1/signers/{name}/sign",
		metricspkg.WithHttpMetrics("/v1/signers/{name}/sign", server.withAuth(
			map[string]authpkg.Role{
				http.MethodPost: authpkg.RoleOperator, // sign certificate
			},
			http.HandlerFunc(server.handleSignerSign))))

	server.handler.Handle("/v1/signers/{name}/revoke",
		metricspkg.WithHttpMetrics("/v1/signers/{name}/revoke", server.withAuth(
			map[string]authpkg.Role{
				http.MethodPost: authpkg.RoleOperator, // revoke certificate
			},
			http.HandlerFunc(server.handleSignerRevoke))))

	server.nonTLSHandler.Handle("/v1/crl/{hashOfSignerName:.*}",
		http.HandlerFunc(server.handleGetSignerCRL))

	server.nonTLSHandler.Handle("/v1/aia/{hashOfSignerName:.*}",
		http.HandlerFunc(server.handleGetSignerAIA))

	// Leave this here until the ACME-specific refactor.
	server.handler.PathPrefix("/v1/signers/{name}/acme").
		Handler(http.HandlerFunc(server.handleSignerACME))
}

func (server *Server) registerSecretRoutes() {
	server.handler.Handle("/v1/secrets", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleAny, // get secrets
		},
		http.HandlerFunc(server.handleGetSecrets)))

	server.handler.Handle("/v1/secrets/data/{name:.+}",
		metricspkg.WithHttpMetrics("/v1/secrets/data/{name}", server.withAuth(
			map[string]authpkg.Role{
				http.MethodGet: authpkg.RoleOperator, // get secret (Hashicorp Vault compatible)
			},
			http.HandlerFunc(server.handleGetOrUpdateOrDeleteSecret))))

	server.handler.Handle("/v1/secrets/{name:.+}",
		metricspkg.WithHttpMetrics("/v1/secrets/{name}", server.withAuth(
			map[string]authpkg.Role{
				http.MethodGet:    authpkg.RoleOperator, // get secret
				http.MethodPut:    authpkg.RoleOperator, // insert secret
				http.MethodPost:   authpkg.RoleOperator, // update secret
				http.MethodPatch:  authpkg.RoleOperator, // patch secret
				http.MethodDelete: authpkg.RoleOperator, // delete secret
			},
			http.HandlerFunc(server.handleGetOrUpdateOrDeleteSecret))))
}

func (server *Server) registerCertificateRoutes() {
	server.handler.Handle("/v1/certs", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleAny, // get certs
		},
		http.HandlerFunc(server.handleGetCerts)))

	server.handler.Handle("/v1/certs/{serial}/pem", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleAny, // get cert PEM
		},
		http.HandlerFunc(server.handleGetCertPEM)))
}

func (server *Server) registerMiscRoutes() {
	server.handler.Handle("/v1/logs", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleAuditor, // get logs
		},
		http.HandlerFunc(server.handleGetLogs)))

	server.handler.Handle("/v1/dashboard", server.withAuth(
		map[string]authpkg.Role{
			http.MethodGet: authpkg.RoleAny, // get dashboard
		},
		http.HandlerFunc(server.handleGetDashboard)))

	server.handler.Handle("/v1/token", http.HandlerFunc(server.handleGetToken))

	server.handler.Handle("/v1/health", http.HandlerFunc(server.handleGetHealthStatus))

	server.handler.Handle("/v1/oidc/jwks/kubernetes", http.HandlerFunc(server.handleGetKubernetesJWKS))
}

func (server *Server) registerVaultCompatibilityRoutes() {
	server.handler.Handle("/v1/auth/{mount}/login", http.HandlerFunc(server.handleGetToken))

	server.handler.Handle("/v1/sys/health", http.HandlerFunc(server.handleGetHealthStatus))

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
