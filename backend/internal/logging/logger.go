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
	envLogDBBatchSize     = "LOG_DB_BATCH_SIZE"
	envLogDBFlushInterval = "LOG_DB_FLUSH_INTERVAL"

	CtxKeySaveLogToDB       = ctxKey("saveLogToDB")
	CtxKeyToken             = ctxKey("token")
	CtxKeyUser              = ctxKey("user")
	CtxKeyRoles             = ctxKey("roles")
	CtxKeyEnvironment       = ctxKey("environment")
	CtxKeyAuthorizerToken   = ctxKey("authorizerToken")
	CtxKeyRequestID         = ctxKey("requestID")
	CtxKeyOriginalRequestID = ctxKey("originalRequestID")
)

// LogEntry represents a log entry with level, message, args, and whether to save to DB.
// !IMPORTANT: To be used ONLY in functions that do not have direct access to the logger
type LogEntry struct {
	Level   slog.Level
	Message string
	Args    []any
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

	// Create the standard logger
	stdHandler := slog.NewTextHandler(
		os.Stdout, &slog.HandlerOptions{
			Level: getLogLevel(),
		})

	// Create the database logger
	pgHandler := NewPGHandler(db, batchSize, flushInterval)

	return &StdAndDBLogger{
		stdLogger: slog.New(stdHandler),
		dbLogger:  slog.New(pgHandler),
	}, nil
}

func removeErrorArgs(args []any) []any {
	// remove error pairs (e.g. "error", err) from args to avoid storing them in DB, but keep them in the standard logger
	var filtered []any
	for i := 0; i < len(args)-1; i += 2 {
		key, val := args[i], args[i+1]
		keyStr, isString := key.(string)
		if isError(val) || (isString && (keyStr == "error" || keyStr == "err" || keyStr == "ERROR" || keyStr == "ERR")) {
			continue // skip this pair
		}
		filtered = append(filtered, key, val)
	}
	return filtered
}

func isError(val any) bool {
	_, ok := val.(error)
	return ok
}

func (l *StdAndDBLogger) LogWithContext(ctx context.Context, logEntry *LogEntry) {
	args := append(attrsFromContext(ctx), logEntry.Args...)
	l.stdLogger.Log(ctx, logEntry.Level, logEntry.Message, args...)
	if saveToDB, ok := ctx.Value(CtxKeySaveLogToDB).(bool); ok && saveToDB {
		l.dbLogger.Log(ctx, logEntry.Level, logEntry.Message, removeErrorArgs(args)...)
	}
}

func (l *StdAndDBLogger) InfoWithContext(ctx context.Context, msg string, args ...any) {
	attrs := append(attrsFromContext(ctx), args...)
	l.stdLogger.InfoContext(ctx, msg, attrs...)
	if saveToDB, ok := ctx.Value(CtxKeySaveLogToDB).(bool); ok && saveToDB {
		l.dbLogger.InfoContext(ctx, msg, attrs...)
	}
}

func (l *StdAndDBLogger) Info(r *http.Request, msg string, args ...any) {
	attrs := append(attrsFromRequest(r), args...)
	l.stdLogger.InfoContext(r.Context(), msg, attrs...)
	if saveToDB, ok := r.Context().Value(CtxKeySaveLogToDB).(bool); ok && saveToDB {
		l.dbLogger.InfoContext(r.Context(), msg, attrs...)
	}
}

func (l *StdAndDBLogger) ErrorWithContext(ctx context.Context, msg string, args ...any) {
	attrs := append(attrsFromContext(ctx), args...)
	l.stdLogger.ErrorContext(ctx, msg, attrs...)
	if saveToDB, ok := ctx.Value(CtxKeySaveLogToDB).(bool); ok && saveToDB {
		l.dbLogger.ErrorContext(ctx, msg, removeErrorArgs(attrs)...)
	}
}

func (l *StdAndDBLogger) Error(r *http.Request, msg string, args ...any) {
	attrs := append(attrsFromRequest(r), args...)
	l.stdLogger.ErrorContext(r.Context(), msg, attrs...)
	if saveToDB, ok := r.Context().Value(CtxKeySaveLogToDB).(bool); ok && saveToDB {
		l.dbLogger.ErrorContext(r.Context(), msg, removeErrorArgs(attrs)...)
	}
}

func (l *StdAndDBLogger) WarnWithContext(ctx context.Context, msg string, args ...any) {
	attrs := append(attrsFromContext(ctx), args...)
	l.stdLogger.WarnContext(ctx, msg, attrs...)
	if saveToDB, ok := ctx.Value(CtxKeySaveLogToDB).(bool); ok && saveToDB {
		l.dbLogger.WarnContext(ctx, msg, removeErrorArgs(attrs)...)
	}
}

func (l *StdAndDBLogger) Warn(r *http.Request, msg string, args ...any) {
	attrs := append(attrsFromRequest(r), args...)
	l.stdLogger.WarnContext(r.Context(), msg, attrs...)
	if saveToDB, ok := r.Context().Value(CtxKeySaveLogToDB).(bool); ok && saveToDB {
		l.dbLogger.WarnContext(r.Context(), msg, removeErrorArgs(attrs)...)
	}
}

func (l *StdAndDBLogger) DebugWithContext(ctx context.Context, msg string, args ...any) {
	attrs := append(attrsFromContext(ctx), args...)
	l.stdLogger.DebugContext(ctx, msg, attrs...)
}

func (l *StdAndDBLogger) Debug(r *http.Request, msg string, args ...any) {
	attrs := append(attrsFromRequest(r), args...)
	l.stdLogger.DebugContext(r.Context(), msg, attrs...)
}

func (l *StdAndDBLogger) Close() {
	if l.dbLogger != nil {
		l.dbLogger.Handler().(*PGHandler).Close()
	}
}

func GetTokenInfoFromClaims(idToken *oidc.IDToken, full bool) (string, []string) {
	if full {
		type tokenClaimsFull struct {
			Email string `json:"email"`
			//PreferredUsername string `json:"preferred_username"`
			//Name              string `json:"name"`
			Sub         string `json:"sub"`
			RealmAccess struct {
				Roles []string `json:"roles"`
			} `json:"realm_access"`
			ResourceAccess map[string]struct {
				Roles []string `json:"roles"`
			} `json:"resource_access"`
		}
		var c tokenClaimsFull
		var roles []string
		if err := idToken.Claims(&c); err == nil {
			roles = c.RealmAccess.Roles
			for _, ra := range c.ResourceAccess {
				roles = append(roles, ra.Roles...)
			}
		}
		return firstNonEmpty(c.Email /*c.PreferredUsername, c.Name,*/, c.Sub), roles
	}

	type tokenClaims struct {
		Email string `json:"email"`
		//PreferredUsername string `json:"preferred_username"`
		//Name              string `json:"name"`
		Sub string `json:"sub"`
	}

	var c tokenClaims
	if err := idToken.Claims(&c); err == nil {
		return firstNonEmpty(c.Email /*c.PreferredUsername, c.Name,*/, c.Sub), nil
	}
	return idToken.Subject, nil
}

// ---- Helpers ---- //

func attrsFromContext(ctx context.Context) []any {
	var attrs []any
	if ctx != nil {
		if token, ok := ctx.Value(CtxKeyToken).(*oidc.IDToken); ok {
			if user, ok := ctx.Value(CtxKeyUser).(string); ok {
				attrs = append(attrs,
					slog.Group("token",
						slog.String("user", user),
						slog.String("issuer", token.Issuer),
					),
				)
			}
		}
		if environment, ok := ctx.Value(CtxKeyEnvironment).(string); ok {
			attrs = append(attrs, slog.String(string(CtxKeyEnvironment), environment))
		}
		if originalReqID, ok := ctx.Value(CtxKeyOriginalRequestID).(uuid.UUID); ok {
			attrs = append(attrs, slog.String(string(CtxKeyOriginalRequestID), originalReqID.String()))
		}
		if authorizerToken, ok := ctx.Value(CtxKeyAuthorizerToken).(*oidc.IDToken); ok {
			user, _ := GetTokenInfoFromClaims(authorizerToken, false)
			attrs = append(attrs,
				slog.Group("authorizerToken",
					slog.String("user", user),
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

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
