// Copyright 2025 KeyAuthority.

package logging

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

const (
	envLogLevel           = "LOG_LEVEL"
	envLogDBBatchSize     = "LOG_DB_BATCH_SIZE"
	envLogDBFlushInterval = "LOG_DB_FLUSH_INTERVAL"
)

type CtxKeyWriteLogToDB struct{}
type CtxKeyToken struct{}
type CtxKeyTokenInfo struct{}
type CtxKeyEnvironment struct{}

func (c *CtxKeyEnvironment) String() string {
	return "environment"
}

type Logger struct {
	stdLogger *slog.Logger
	dbLogger  *slog.Logger
}

func NewLogger(ctx context.Context, db *sql.DB) (*Logger, error) {
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

	return &Logger{
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

func (l *Logger) InfoWithContext(ctx context.Context, msg string, args ...any) {
	attrs := append(attrsFromContext(ctx), args...)
	l.stdLogger.InfoContext(ctx, msg, attrs...)
	if saveToDB, ok := ctx.Value(CtxKeyWriteLogToDB{}).(bool); ok && saveToDB {
		l.dbLogger.InfoContext(ctx, msg, attrs...)
	}
}

func (l *Logger) Info(r *http.Request, msg string, args ...any) {
	attrs := append(attrsFromRequest(r), args...)
	l.stdLogger.InfoContext(r.Context(), msg, attrs...)
	if saveToDB, ok := r.Context().Value(CtxKeyWriteLogToDB{}).(bool); ok && saveToDB {
		l.dbLogger.InfoContext(r.Context(), msg, attrs...)
	}
}

func (l *Logger) ErrorWithContext(ctx context.Context, msg string, args ...any) {
	attrs := append(attrsFromContext(ctx), args...)
	l.stdLogger.ErrorContext(ctx, msg, attrs...)
	if saveToDB, ok := ctx.Value(CtxKeyWriteLogToDB{}).(bool); ok && saveToDB {
		l.dbLogger.ErrorContext(ctx, msg, removeErrorArgs(attrs)...)
	}
}

func (l *Logger) Error(r *http.Request, msg string, args ...any) {
	attrs := append(attrsFromRequest(r), args...)
	l.stdLogger.ErrorContext(r.Context(), msg, attrs...)
	if saveToDB, ok := r.Context().Value(CtxKeyWriteLogToDB{}).(bool); ok && saveToDB {
		l.dbLogger.ErrorContext(r.Context(), msg, removeErrorArgs(attrs)...)
	}
}

func (l *Logger) WarnWithContext(ctx context.Context, msg string, args ...any) {
	attrs := append(attrsFromContext(ctx), args...)
	l.stdLogger.WarnContext(ctx, msg, attrs...)
	if saveToDB, ok := ctx.Value(CtxKeyWriteLogToDB{}).(bool); ok && saveToDB {
		l.dbLogger.WarnContext(ctx, msg, removeErrorArgs(attrs)...)
	}
}

func (l *Logger) Warn(r *http.Request, msg string, args ...any) {
	attrs := append(attrsFromRequest(r), args...)
	l.stdLogger.WarnContext(r.Context(), msg, attrs...)
	if saveToDB, ok := r.Context().Value(CtxKeyWriteLogToDB{}).(bool); ok && saveToDB {
		l.dbLogger.WarnContext(r.Context(), msg, removeErrorArgs(attrs)...)
	}
}

func (l *Logger) DebugWithContext(ctx context.Context, msg string, args ...any) {
	attrs := append(attrsFromContext(ctx), args...)
	l.stdLogger.DebugContext(ctx, msg, attrs...)
}

func (l *Logger) Debug(r *http.Request, msg string, args ...any) {
	attrs := append(attrsFromRequest(r), args...)
	l.stdLogger.DebugContext(r.Context(), msg, attrs...)
}

func (l *Logger) Close() {
	if l.dbLogger != nil {
		l.dbLogger.Handler().(*PGHandler).Close()
	}
}

type TokenInfo struct {
	Sub               string   `json:"sub"`
	Email             string   `json:"email,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	ExternalIssuer    string   `json:"external_iss,omitempty"`
	ExternalSubject   string   `json:"external_sub,omitempty"`
	ExternalKeyID     string   `json:"external_kid,omitempty"`
	Roles             []string `json:"roles,omitempty"`
}

func (t *TokenInfo) GetHumanReadableUsername() string {
	return firstNonEmpty(t.PreferredUsername, t.Email, t.Sub)
}

func (t *TokenInfo) ToSlogAttrs() []any {
	user := t.GetHumanReadableUsername()
	attrs := []any{
		slog.String("user", user),
	}
	if t.Sub != user {
		attrs = append(attrs, slog.String("sub", t.Sub))
	}
	return attrs
}

func (t *TokenInfo) ToMap() map[string]string {
	user := t.GetHumanReadableUsername()
	var m = make(map[string]string)
	m["user"] = user
	if t.Sub != user {
		m["sub"] = t.Sub
	}
	return m
}

func (t *TokenInfo) ToSlogAttrsWithJWTAuthzGrant() []any {
	attrs := t.ToSlogAttrs()
	externalAttrs := []any{}
	if t.ExternalIssuer != "" {
		externalAttrs = append(externalAttrs, slog.String("iss", t.ExternalIssuer))
	}
	if t.ExternalSubject != "" {
		externalAttrs = append(externalAttrs, slog.String("sub", t.ExternalSubject))
	}
	if t.ExternalKeyID != "" {
		externalAttrs = append(externalAttrs, slog.String("kid", t.ExternalKeyID))
	}
	if len(externalAttrs) > 0 {
		attrs = append(attrs, slog.Group("externalJWT", externalAttrs...))
	}
	return attrs
}

// GetLoggerFromContext retrieves the user, external issuer, external subject, roles
func GetTokenInfoFromClaims(idToken *oidc.IDToken, includeRoles bool) *TokenInfo {
	if includeRoles {
		type tokenClaimsFull struct {
			Sub               string `json:"sub"`
			Email             string `json:"email"`
			PreferredUsername string `json:"preferred_username"`
			ExternalIssuer    string `json:"external_iss"`
			ExternalSubject   string `json:"external_sub"`
			ExternalKeyID     string `json:"external_kid"`
			RealmAccess       struct {
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
		return &TokenInfo{
			Sub:               c.Sub,
			Email:             c.Email,
			PreferredUsername: c.PreferredUsername,
			ExternalIssuer:    c.ExternalIssuer,
			ExternalSubject:   c.ExternalSubject,
			ExternalKeyID:     c.ExternalKeyID,
			Roles:             roles,
		}
	}

	type tokenClaims struct {
		Sub               string `json:"sub"`
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
		ExternalIssuer    string `json:"external_iss"`
		ExternalSubject   string `json:"external_sub"`
		ExternalKeyID     string `json:"external_kid"`
	}

	var c tokenClaims
	if err := idToken.Claims(&c); err == nil {
		return &TokenInfo{
			Sub:               c.Sub,
			Email:             c.Email,
			PreferredUsername: c.PreferredUsername,
			ExternalIssuer:    c.ExternalIssuer,
			ExternalSubject:   c.ExternalSubject,
			ExternalKeyID:     c.ExternalKeyID,
		}
	}
	return &TokenInfo{
		Sub: idToken.Subject,
	}
}

// ---- Helpers ---- //

func attrsFromContext(ctx context.Context) []any {
	var attrs []any
	if ctx != nil {
		// actor
		if tokenInfo, ok := ctx.Value(CtxKeyTokenInfo{}).(*TokenInfo); ok && tokenInfo != nil {
			tokenAttrs := tokenInfo.ToSlogAttrsWithJWTAuthzGrant()
			if len(tokenAttrs) > 0 {
				attrs = append(attrs, slog.Group("token", tokenAttrs...))
			}
		}

		// environment
		if environment, ok := ctx.Value(CtxKeyEnvironment{}).(string); ok {
			attrs = append(attrs, slog.String((&CtxKeyEnvironment{}).String(), environment))
		}

	}
	return attrs
}

func attrsFromRequest(r *http.Request) []any {
	var attrs []any
	if r != nil {
		path := r.URL.Path
		/*if unescapedPath, err := url.PathUnescape(path); err == nil {
			path = unescapedPath
		}*/
		query := r.URL.RawQuery
		/*if unescapedQuery, err := url.QueryUnescape(query); err == nil {
			query = unescapedQuery
		}*/
		reqURL := path
		if query != "" {
			reqURL += "?" + query
		}

		attrs = append(attrsFromContext(r.Context()),
			slog.String("method", r.Method),
			slog.String("url", reqURL),
		)
		if r.RemoteAddr != "" {
			attrs = append(attrs, slog.String("remoteAddr", r.RemoteAddr))
		}
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
