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

// PGHandler implements slog.Handler with async batching
type PGHandler struct {
	db            *sql.DB
	minLevel      slog.Level
	ch            chan slog.Record
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
		ch:            make(chan slog.Record, batchSize*2),
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

	var batch []slog.Record

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
			// drain queue before exit
			for {
				select {
				case rec := <-h.ch:
					batch = append(batch, rec)
				default:
					flush()
					return
				}
			}
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

func firstAttrString(attrs []slog.Attr, key string) string {
	for _, a := range attrs {
		if a.Key == key {
			return a.Value.String()
		}
		if a.Value.Kind() == slog.KindGroup {
			if v := firstAttrString(a.Value.Group(), key); v != "" {
				return v
			}
		}
	}
	return ""
}

// insertBatch performs a single INSERT for the collected records.
func (h *PGHandler) insertBatch(batch []slog.Record) {
	if len(batch) == 0 {
		return
	}

	var (
		buf          bytes.Buffer
		jsonHandler  = slog.NewJSONHandler(&buf, &slog.HandlerOptions{AddSource: false})
		jsonRows     = make([]string, 0, len(batch))
		logTimes     = make([]time.Time, 0, len(batch))
		levels       = make([]string, 0, len(batch))
		msgs         = make([]string, 0, len(batch))
		logUsers     = make([]string, 0, len(batch))
		environments = make([]string, 0, len(batch))
	)

	// Serialize in worker (off request path)
	for _, rec := range batch {
		buf.Reset()
		if err := jsonHandler.Handle(context.Background(), rec); err != nil {
			log.Printf("[pgslog] format record failed: %v", err)
			continue
		}

		var attrs []slog.Attr
		rec.Attrs(func(a slog.Attr) bool {
			attrs = append(attrs, a)
			return true
		})

		jsonRows = append(jsonRows, strings.TrimSpace(buf.String()))
		logTimes = append(logTimes, rec.Time)
		levels = append(levels, rec.Level.String())
		msgs = append(msgs, rec.Message)
		logUsers = append(logUsers, firstAttrString(attrs, "user"))
		environments = append(environments, firstAttrString(attrs, "environment"))
	}

	if len(jsonRows) == 0 {
		return
	}

	// Build multi-value insert query.
	var (
		sb    strings.Builder
		args  []any
		count = 1
	)
	sb.WriteString(`INSERT INTO logs (entry, log_time, level, msg, log_user, environment) VALUES `)

	for i, row := range jsonRows {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, "($%d::jsonb, $%d, $%d, $%d, $%d, $%d)", count, count+1, count+2, count+3, count+4, count+5)
		args = append(args, row, logTimes[i], levels[i], msgs[i], logUsers[i], environments[i])
		count += 6
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := h.db.ExecContext(ctx, sb.String(), args...); err != nil {
		log.Printf("[pgslog] batch insert failed: %v", err)
	}
}

// Handle adds the record to the buffer for async insertion.
func (h *PGHandler) Handle(_ context.Context, r slog.Record) error {
	if r.Level < h.minLevel {
		return nil
	}

	// Clone and enqueue quickly; heavy work happens in worker.
	rec := r.Clone()

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
