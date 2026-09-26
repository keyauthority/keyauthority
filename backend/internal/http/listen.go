// Copyright 2025 KeyAuthority.

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

// ListenAndServe starts the HTTP, HTTPS, and metrics servers and returns them as a slice of *http.Server.
// The servers are returned so that they can be properly shut down later.
func (server *Server) ListenAndServe(ctx context.Context) []*http.Server {
	metricspkg.SetupMetrics()
	server.metricsHandler.Handle("/metrics", metricspkg.MetricsHandler())

	metricsPort := os.Getenv(envMetricsPort)
	metricsServer := &http.Server{
		Addr:    ":" + metricsPort,
		Handler: server.metricsHandler,
	}

	go func() {
		server.log.InfoWithContext(ctx, "metrics server starting", "port", metricsPort)
		if err := metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			server.log.ErrorWithContext(ctx, "metrics server stopped unexpectedly",
				"port", metricsPort,
				"error", err)
		}
	}()

	httpPort := os.Getenv(envHTTPPort)
	httpServer := &http.Server{
		Addr:    ":" + httpPort,
		Handler: server.withSecurityHeaders(server.withCORS(server.nonTLSHandler)),
	}

	go func() {
		server.log.InfoWithContext(ctx, "HTTP server starting", "port", httpPort)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			server.log.ErrorWithContext(ctx, "HTTP server stopped unexpectedly",
				"port", httpPort,
				"error", err)
		}
	}()

	tlsCert := os.Getenv(envTLSCert)
	tlsKey := os.Getenv(envTLSKey)
	if tlsCert == "" || tlsKey == "" {
		return []*http.Server{httpServer, metricsServer}
	}

	httpsPort := os.Getenv(envHTTPSPort)
	httpsServer := &http.Server{
		Addr:    ":" + httpsPort,
		Handler: server.withSecurityHeaders(server.withCORS(server.handler)),
	}

	go func() {
		server.log.InfoWithContext(ctx, "HTTPS server starting", "port", httpsPort)
		if err := httpsServer.ListenAndServeTLS(tlsCert, tlsKey); err != nil &&
			!errors.Is(err, http.ErrServerClosed) {
			server.log.ErrorWithContext(ctx, "HTTPS server stopped unexpectedly",
				"port", httpsPort,
				"error", err)
		}
	}()

	return []*http.Server{httpServer, httpsServer, metricsServer}
}
