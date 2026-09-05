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
	"os"
	"time"
)

const (
	envCRLRefreshInterval       = "CRL_REFRESH_INTERVAL"
	envStoreCleanupInterval     = "STORE_CLEANUP_INTERVAL"
	envInventoryRefreshInterval = "INVENTORY_REFRESH_INTERVAL"
)

func (server *Server) RunPeriodicTasks(ctx context.Context) {
	// CRL recreation
	go func() {
		intervalStr := os.Getenv(envCRLRefreshInterval)
		if intervalStr == "" {
			intervalStr = "72h"
		}
		crlRecreationInterval, err := time.ParseDuration(intervalStr)
		if err != nil {
			server.log.WarnWithContext(ctx,
				"invalid CRL refresh interval, using default of 72h",
				"error", err, "intervalStr", intervalStr)
			crlRecreationInterval = 72 * time.Hour
		}

		ticker := time.NewTicker(crlRecreationInterval)
		defer ticker.Stop()

		for {
			successCount, failureCount, err := server.recreateCRLs(ctx)
			if err != nil {
				server.log.WarnWithContext(ctx, "couldn't recreate CRLs", "error", err)
			} else {
				server.log.DebugWithContext(ctx, "CRL recreation completed",
					"succeeded", successCount, "failed", failureCount)
			}

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()

	// Store Cleanup
	go func() {
		intervalStr := os.Getenv(envStoreCleanupInterval)
		if intervalStr == "" {
			intervalStr = "24h"
		}
		storeCleanupInterval, err := time.ParseDuration(intervalStr)
		if err != nil {
			server.log.WarnWithContext(ctx,
				"invalid store cleanup interval, using default of 24h",
				"error", err, "intervalStr", intervalStr)
			storeCleanupInterval = 24 * time.Hour
		}

		time.Sleep(storeCleanupInterval) // initial delay before first cleanup
		ticker := time.NewTicker(storeCleanupInterval)
		defer ticker.Stop()

		for {
			if err := server.db.RunCleanupTasks(ctx); err != nil {
				server.log.WarnWithContext(ctx,
					"couldn't perform store cleanup tasks", "error", err)
			} else {
				server.log.DebugWithContext(ctx,
					"store cleanup tasks completed")
			}

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()

	// Store Inventory Refresh
	go func() {
		intervalStr := os.Getenv(envInventoryRefreshInterval)
		if intervalStr == "" {
			intervalStr = "30m"
		}
		inventoryRefreshInterval, err := time.ParseDuration(intervalStr)
		if err != nil {
			server.log.WarnWithContext(ctx,
				"invalid inventory refresh interval, using default of 30m",
				"error", err, "intervalStr", intervalStr)
			inventoryRefreshInterval = 30 * time.Minute
		}

		ticker := time.NewTicker(inventoryRefreshInterval)
		defer ticker.Stop()

		for {
			if err := server.db.RefreshInventoryMetrics(ctx); err != nil {
				server.log.WarnWithContext(ctx,
					"couldn't refresh inventory metrics", "error", err)
			} else {
				server.log.DebugWithContext(ctx,
					"inventory metrics refreshed")
			}

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()

	// ACME Cleanup
	if server.acme != nil {
		go server.acme.RunCleanup(ctx)
	}
}

func (server *Server) recreateCRLs(ctx context.Context) (int, int, error) {
	signers, err := server.db.GetAllSigners(ctx)
	if err != nil {
		return 0, 0, err
	}

	successCount := 0
	for _, signerName := range signers {
		signer, err := server.db.LoadSigner(ctx, signerName)
		if err != nil {
			server.log.WarnWithContext(ctx, "couldn't load signer", "signer", signerName, "error", err)
			continue
		}

		existingCRL, err := server.db.GetSignerCRL(ctx, signerName)
		if err != nil {
			server.log.WarnWithContext(ctx, "couldn't get existing CRL", "signer", signerName, "error", err)
			continue
		}

		crl, err := signer.SignCRL(existingCRL, nil)
		if err != nil {
			server.log.WarnWithContext(ctx, "couldn't create CRL", "signer", signerName, "error", err)
			continue
		}

		if err := server.db.SetSignerCRL(ctx, signerName, crl); err != nil {
			server.log.WarnWithContext(ctx, "couldn't store CRL", "signer", signerName, "error", err)
			continue
		}

		server.log.InfoWithContext(ctx, "CRL updated", "signer", signerName)
		successCount++
	}
	return successCount, len(signers) - successCount, nil
}
