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
	"errors"
	"net/http"
	"os"

	metricspkg "github.com/keyauthority/keyauthority/internal/metrics"
)

const (
	envHTTPPort    = "HTTP_PORT"
	envHTTPSPort   = "HTTPS_PORT"
	envMetricsPort = "METRICS_PORT"
)

func (server *Server) ListenAndServe(ctx context.Context) {
	metricspkg.SetupMetrics()
	server.metricsHandler.Handle("/metrics", metricspkg.MetricsHandler())

	metricsPort := os.Getenv(envMetricsPort)
	server.metricsServer = &http.Server{
		Addr:    ":" + metricsPort,
		Handler: server.metricsHandler,
	}

	go func() {
		server.log.InfoWithContext(ctx, "metrics server starting", "port", metricsPort)
		if err := server.metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			server.log.ErrorWithContext(ctx, "metrics server stopped unexpectedly",
				"port", metricsPort,
				"error", err)
		}
	}()

	httpPort := os.Getenv(envHTTPPort)
	server.httpServer = &http.Server{
		Addr:    ":" + httpPort,
		Handler: server.withSecurityHeaders(server.withCORS(server.nonTLSHandler)),
	}

	go func() {
		server.log.InfoWithContext(ctx, "HTTP server starting", "port", httpPort)
		if err := server.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			server.log.ErrorWithContext(ctx, "HTTP server stopped unexpectedly",
				"port", httpPort,
				"error", err)
		}
	}()

	tlsCert := os.Getenv(envTLSCert)
	tlsKey := os.Getenv(envTLSKey)
	if tlsCert == "" || tlsKey == "" {
		return
	}

	httpsPort := os.Getenv(envHTTPSPort)
	server.httpsServer = &http.Server{
		Addr:    ":" + httpsPort,
		Handler: server.withSecurityHeaders(server.withCORS(server.handler)),
	}

	go func() {
		server.log.InfoWithContext(ctx, "HTTPS server starting", "port", httpsPort)
		if err := server.httpsServer.ListenAndServeTLS(tlsCert, tlsKey); err != nil &&
			!errors.Is(err, http.ErrServerClosed) {
			server.log.ErrorWithContext(ctx, "HTTPS server stopped unexpectedly",
				"port", httpsPort,
				"error", err)
		}
	}()
}
