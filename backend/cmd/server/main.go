// Copyright 2025 KeyAuthority.

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	httppkg "github.com/keyauthority/keyauthority/internal/http"
)

var version string

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	server := httppkg.NewServer(version)
	defer server.Close()

	server.ConnectDatabase(ctx)
	server.CreateLogger(ctx)
	server.SetHttpTransport(ctx)
	server.CreateAuthenticator(ctx)
	server.CreateACMEService(ctx)

	server.SetHandlers()
	httpServers := server.ListenAndServe(ctx)
	server.RunPeriodicTasks(ctx)

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, s := range httpServers {
		if err := s.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintf(os.Stderr, "server shutdown failed: %v\n", err)
		}
	}
}
