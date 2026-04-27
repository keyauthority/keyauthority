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

package logging

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"log"
	"log/slog"
	"strings"
	"sync"
	"time"
)

type batchedRecord struct {
	JSON string
}

// PGHandler implements slog.Handler with async batching
type PGHandler struct {
	db            *sql.DB
	minLevel      slog.Level
	ch            chan batchedRecord
	wg            sync.WaitGroup
	flushInterval time.Duration
	batchSize     int
	ctx           context.Context
	cancel        context.CancelFunc
}

// NewPGHandler creates a new batched Postgres slog handler.
func NewPGHandler(db *sql.DB, batchSize int, flushInterval time.Duration) *PGHandler {
	ctx, cancel := context.WithCancel(context.Background())
	h := &PGHandler{
		db:            db,
		minLevel:      slog.LevelInfo,
		ch:            make(chan batchedRecord, batchSize*2),
		batchSize:     batchSize,
		flushInterval: flushInterval,
		ctx:           ctx,
		cancel:        cancel,
	}

	h.wg.Add(1)
	go h.worker()
	return h
}

// worker consumes records and writes them to Postgres in batches.
func (h *PGHandler) worker() {
	defer h.wg.Done()
	ticker := time.NewTicker(h.flushInterval)
	defer ticker.Stop()

	var batch []batchedRecord

	flush := func() {
		if len(batch) == 0 {
			return
		}
		h.insertBatch(batch)
		batch = batch[:0]
	}

	for {
		select {
		case <-h.ctx.Done():
			flush()
			return
		case rec := <-h.ch:
			batch = append(batch, rec)
			if len(batch) >= h.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// insertBatch performs a single INSERT for the collected records.
func (h *PGHandler) insertBatch(batch []batchedRecord) {
	if len(batch) == 0 {
		return
	}

	// Build multi-value insert query.
	var (
		sb    strings.Builder
		args  []any
		count = 1
	)
	sb.WriteString(`INSERT INTO logs (entry) VALUES `)

	for i, r := range batch {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, "($%d::jsonb)", count)
		args = append(args, r.JSON)
		count++
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := h.db.ExecContext(ctx, sb.String(), args...); err != nil {
		log.Printf("[pgslog] batch insert failed: %v", err)
	}
}

// Handle adds the record to the buffer for async insertion.
func (h *PGHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level < h.minLevel {
		return nil
	}

	// Convert record to JSON using a standard slog JSON handler.
	var buf bytes.Buffer
	jsonHandler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{AddSource: false})
	if err := jsonHandler.Handle(ctx, r); err != nil {
		return fmt.Errorf("format record: %w", err)
	}

	rec := batchedRecord{
		JSON: buf.String(),
	}

	select {
	case h.ch <- rec:
	default:
		// channel full, drop log (prevent blocking)
		log.Printf("[pgslog] dropped log (channel full): %s", r.Message)
	}
	return nil
}

func (h *PGHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.minLevel
}

func (h *PGHandler) WithAttrs(attrs []slog.Attr) slog.Handler { return h }
func (h *PGHandler) WithGroup(name string) slog.Handler       { return h }

// Close flushes remaining logs and stops the worker.
func (h *PGHandler) Close() {
	h.cancel()
	h.wg.Wait()
}
