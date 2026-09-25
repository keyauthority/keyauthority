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
