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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/mux"

	acmepkg "github.com/keyauthority/keyauthority/internal/acme"
	authpkg "github.com/keyauthority/keyauthority/internal/auth"
	cachepkg "github.com/keyauthority/keyauthority/internal/cache"
	databasepkg "github.com/keyauthority/keyauthority/internal/database"
	loggingpkg "github.com/keyauthority/keyauthority/internal/logging"
)

const (
	envVersion    = "VERSION"
	envTruststore = "TRUSTSTORE"
	envTLSCert    = "TLS_CERT"
	envTLSKey     = "TLS_KEY"
)

type Server struct {
	version  string
	log      *loggingpkg.Logger
	db       *databasepkg.Database
	acme     *acmepkg.Service
	envCache *cachepkg.Cache // Cache prefix:name/id -> environment

	handler        *mux.Router
	metricsHandler *mux.Router
	nonTLSHandler  *mux.Router

	httpServer    *http.Server
	httpsServer   *http.Server
	metricsServer *http.Server
}

func NewServer() *Server {
	handler := mux.NewRouter()
	nonTLSHandler := handler
	if os.Getenv(envTLSKey) != "" && os.Getenv(envTLSCert) != "" {
		nonTLSHandler = mux.NewRouter()
	}

	return &Server{
		version:        os.Getenv(envVersion),
		envCache:       cachepkg.NewCache(),
		handler:        handler,
		nonTLSHandler:  nonTLSHandler,
		metricsHandler: mux.NewRouter(),
	}
}

func (server *Server) ConnectDatabase(ctx context.Context) {
	db, err := databasepkg.NewDatabase(ctx)
	if err != nil {
		fmt.Printf("couldn't connect to database: %v", err)
		return
	}
	server.db = db
}

func (server *Server) CreateLogger(ctx context.Context) {
	log, err := loggingpkg.NewLogger(ctx, server.db.DB)
	if err != nil {
		fmt.Printf("couldn't set up logger: %v", err)
		return
	}
	server.log = log
	server.log.InfoWithContext(ctx, "logger ready")
}

func (server *Server) SetHttpTransport(ctx context.Context) {
	caPool, err := x509.SystemCertPool()
	if err != nil {
		server.log.ErrorWithContext(ctx, "couldn't load system cert pool",
			"error", err)
		return
	}

	// Load extra CA certificates from file paths
	paths := os.Getenv(envTruststore)
	if paths != "" {
		paths := strings.SplitSeq(paths, ",")
		for path := range paths {
			caCert, err := os.ReadFile(strings.TrimSpace(path))
			if err != nil {
				server.log.WarnWithContext(ctx, "couldn't load CA from file",
					"path", path, "error", err)
				continue
			}
			if ok := caPool.AppendCertsFromPEM(caCert); !ok {
				server.log.WarnWithContext(ctx, "couldn't append CA from file",
					"path", path)
			}
		}
	}

	defaultTransport := http.DefaultTransport.(*http.Transport)
	if defaultTransport.TLSClientConfig == nil {
		defaultTransport.TLSClientConfig = &tls.Config{}
	}
	defaultTransport.TLSClientConfig.RootCAs = caPool
	defaultTransport.TLSClientConfig.InsecureSkipVerify = false
	defaultTransport.TLSClientConfig.MinVersion = tls.VersionTLS12
}

func (server *Server) CreateAuthenticator(ctx context.Context) {
	authpkg.SetupAuthenticator()
	server.log.InfoWithContext(ctx, "authenticator ready")
}

func (server *Server) CreateACMEService(ctx context.Context) {
	server.acme = acmepkg.NewService(server.log, server.db)
	server.log.InfoWithContext(ctx, "ACME service ready")
}

func (server *Server) Shutdown(ctx context.Context) error {
	var shutdownErrors []error

	for _, s := range []*http.Server{
		server.httpsServer,
		server.httpServer,
		server.metricsServer,
	} {
		if s == nil {
			continue
		}

		if err := s.Shutdown(ctx); err != nil {
			shutdownErrors = append(shutdownErrors, err)
		}
	}

	return errors.Join(shutdownErrors...)
}

// Close releases dependencies after all HTTP servers have been shut down.
func (server *Server) Close() {
	if server.db != nil {
		server.db.Close()
	}
	if server.log != nil {
		server.log.Close()
	}
}
