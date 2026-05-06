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
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
)

type ctxKey string

const (
	envLogLevel           = "LOG_LEVEL"
	envLogDBEnabled       = "LOG_DB_ENABLED"
	envLogDBBatchSize     = "LOG_DB_BATCH_SIZE"
	envLogDBFlushInterval = "LOG_DB_FLUSH_INTERVAL"

	CtxKeyToken             = ctxKey("token")
	CtxKeyEnvironment       = ctxKey("environment")
	CtxKeyAuthorizerToken   = ctxKey("authorizerToken")
	CtxKeyProviderIndex     = ctxKey("providerIndex")
	CtxKeyRequestID         = ctxKey("requestID")
	CtxKeyOriginalRequestID = ctxKey("originalRequestID")
)

// LogEntry represents a log entry with level, message, args, and whether to save to DB.
// To be used only in functions that do not have direct access to the logger
type LogEntry struct {
	Level    slog.Level
	Message  string
	Args     []any
	SaveToDB bool
}

type StdAndDBLogger struct {
	stdLogger *slog.Logger
	dbLogger  *slog.Logger
}

func NewLogger(ctx context.Context, db *sql.DB) (*StdAndDBLogger, error) {
	batchSizeStr := os.Getenv(envLogDBBatchSize)
	if batchSizeStr == "" {
		batchSizeStr = "50" // default
	}
	batchSize, err := strconv.Atoi(batchSizeStr)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse batch size: %v", err)
	}

	flushIntervalStr := os.Getenv(envLogDBFlushInterval)
	if flushIntervalStr == "" {
		flushIntervalStr = "1m" // default
	}
	flushInterval, err := time.ParseDuration(flushIntervalStr)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse flush interval: %v", err)
	}

	stdHandler := slog.NewTextHandler(
		os.Stdout, &slog.HandlerOptions{
			Level: getLogLevel(),
		})

	// If LOG_DB_ENABLED is not true, we only log to stdout
	if os.Getenv(envLogDBEnabled) != "true" {
		return &StdAndDBLogger{
			stdLogger: slog.New(stdHandler),
			dbLogger:  nil,
		}, nil
	}

	// Try to create the PGHandler to log to Postgres
	pgHandler := NewPGHandler(db, batchSize, flushInterval)

	return &StdAndDBLogger{
		stdLogger: slog.New(stdHandler),
		dbLogger:  slog.New(pgHandler),
	}, nil
}

func (l *StdAndDBLogger) LogWithContext(ctx context.Context, logEntry *LogEntry) {
	l.stdLogger.Log(ctx, logEntry.Level, logEntry.Message, logEntry.Args...)
	if logEntry.Level != slog.LevelDebug && logEntry.SaveToDB && l.dbLogger != nil {
		l.dbLogger.Log(ctx, logEntry.Level, logEntry.Message, logEntry.Args...)
	}
}

func (l *StdAndDBLogger) InfoWithContext(ctx context.Context, writeToDB bool, msg string, args ...any) {
	l.stdLogger.Info(msg, append(attrsFromContext(ctx), args...)...)
	if writeToDB && l.dbLogger != nil {
		l.dbLogger.Info(msg, append(attrsFromContext(ctx), args...)...)
	}
}

func (l *StdAndDBLogger) Info(r *http.Request, writeToDB bool, msg string, args ...any) {
	l.stdLogger.Info(msg, append(attrsFromRequest(r), args...)...)
	if writeToDB && l.dbLogger != nil {
		l.dbLogger.Info(msg, append(attrsFromRequest(r), args...)...)
	}
}

func (l *StdAndDBLogger) ErrorWithContext(ctx context.Context, writeToDB bool, msg string, args ...any) {
	l.stdLogger.Error(msg, append(attrsFromContext(ctx), args...)...)
	if writeToDB && l.dbLogger != nil {
		l.dbLogger.Error(msg, append(attrsFromContext(ctx), args...)...)
	}
}

func (l *StdAndDBLogger) Error(r *http.Request, writeToDB bool, msg string, args ...any) {
	l.stdLogger.Error(msg, append(attrsFromRequest(r), args...)...)
	if writeToDB && l.dbLogger != nil {
		l.dbLogger.Error(msg, append(attrsFromRequest(r), args...)...)
	}
}

func (l *StdAndDBLogger) WarnWithContext(ctx context.Context, writeToDB bool, msg string, args ...any) {
	l.stdLogger.Warn(msg, append(attrsFromContext(ctx), args...)...)
	if writeToDB && l.dbLogger != nil {
		l.dbLogger.Warn(msg, append(attrsFromContext(ctx), args...)...)
	}
}

func (l *StdAndDBLogger) Warn(r *http.Request, writeToDB bool, msg string, args ...any) {
	l.stdLogger.Warn(msg, append(attrsFromRequest(r), args...)...)
	if writeToDB && l.dbLogger != nil {
		l.dbLogger.Warn(msg, append(attrsFromRequest(r), args...)...)
	}
}

func (l *StdAndDBLogger) DebugWithContext(ctx context.Context, msg string, args ...any) {
	l.stdLogger.Debug(msg, append(attrsFromContext(ctx), args...)...)
}

func (l *StdAndDBLogger) Debug(r *http.Request, msg string, args ...any) {
	l.stdLogger.Debug(msg, append(attrsFromRequest(r), args...)...)
}

func (l *StdAndDBLogger) Close() {
	if l.dbLogger != nil {
		l.dbLogger.Handler().(*PGHandler).Close()
	}
}

func GetUser(idToken *oidc.IDToken) string {
	type MyClaims struct {
		Email string `json:"email"`
		//PreferredUsername string `json:"preferred_username"`
		//Name              string `json:"name"`
	}

	var c MyClaims
	if err := idToken.Claims(&c); err == nil {
		if c.Email != "" {
			return c.Email
		}
		/*if c.PreferredUsername != "" {
			return c.PreferredUsername
		}
		if c.Name != "" {
			return c.Name
		}*/
	}
	return idToken.Subject
}

// ---- Helpers ---- //

func attrsFromContext(ctx context.Context) []any {
	var attrs []any
	if ctx != nil {
		if token, ok := ctx.Value(CtxKeyToken).(*oidc.IDToken); ok {
			attrs = append(attrs,
				slog.Group("token",
					slog.String("user", GetUser(token)),
					slog.String("issuer", token.Issuer),
				),
			)
		}
		if environment, ok := ctx.Value(CtxKeyEnvironment).(string); ok {
			attrs = append(attrs, slog.String(string(CtxKeyEnvironment), environment))
		}
		if originalReqID, ok := ctx.Value(CtxKeyOriginalRequestID).(uuid.UUID); ok {
			attrs = append(attrs, slog.String(string(CtxKeyOriginalRequestID), originalReqID.String()))
		}
		if authorizerToken, ok := ctx.Value(CtxKeyAuthorizerToken).(*oidc.IDToken); ok {
			attrs = append(attrs,
				slog.Group("authorizerToken",
					slog.String("user", GetUser(authorizerToken)),
					slog.String("issuer", authorizerToken.Issuer),
				),
			)
		}
		if requestID, ok := ctx.Value(CtxKeyRequestID).(uuid.UUID); ok {
			attrs = append(attrs, slog.String(string(CtxKeyRequestID), requestID.String()))
		}
	}
	return attrs
}

func attrsFromRequest(r *http.Request) []any {
	var attrs []any
	if r != nil {
		// Try to unescape URL for better readability
		path := r.URL.Path
		if unescapedPath, err := url.PathUnescape(path); err == nil {
			path = unescapedPath
		}
		query := r.URL.RawQuery
		if unescapedQuery, err := url.QueryUnescape(query); err == nil {
			query = unescapedQuery
		}
		reqURL := path
		if query != "" {
			reqURL += "?" + query
		}

		attrs = append(attrsFromContext(r.Context()),
			slog.String("method", r.Method),
			slog.String("url", reqURL),
		)
	}
	return attrs
}

func getLogLevel() slog.Level {
	levelStr := os.Getenv(envLogLevel)
	switch levelStr {
	case "debug", "DEBUG":
		return slog.LevelDebug
	case "info", "INFO":
		return slog.LevelInfo
	case "warn", "warning", "WARN", "WARNING":
		return slog.LevelWarn
	case "error", "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo // fallback
	}
}
