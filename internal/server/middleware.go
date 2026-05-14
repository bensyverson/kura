package server

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/identity"
)

// principalContextKey is the context key under which requireAuth stashes
// the resolved principal for downstream handlers.
type principalContextKey struct{}

// principalFromContext returns the principal requireAuth resolved for
// this request. ok is false if called outside an authenticated handler —
// a handler reached through requireAuth can rely on ok being true.
func principalFromContext(ctx context.Context) (identity.Principal, bool) {
	p, ok := ctx.Value(principalContextKey{}).(identity.Principal)
	return p, ok
}

// requireAuth resolves the bearer token on every request to a Cedar
// principal before any business-logic handler runs — the "every route
// authenticated before business logic" rule.
//
// A request with no token, or a malformed or expired one, is rejected
// with 401 and the failed authentication is recorded: a rejected
// credential is an audit-worthy security event. A resolved principal is
// stashed in the request context for the handler. The successful
// resolution is deliberately not re-audited here — the interactive
// sign-in was already recorded at the OAuth callback, and the
// per-record access is recorded by the gate; auditing every token
// presentation on top of that would only add noise.
func requireAuth(auth *identity.Authenticator, rec *audit.Recorder, logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.Resolve(bearerToken(r))
		if err != nil {
			if rerr := rec.RecordAuthentication(r.Context(), identity.Principal{}, audit.OutcomeDenied); rerr != nil {
				logger.Error("auth: recording denied authentication", "err", rerr)
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), principalContextKey{}, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// bearerToken extracts the raw token from the Authorization header. It
// accepts the standard "Bearer <token>" form and a bare token; an absent
// header yields the empty string, which Resolve treats as
// unauthenticated.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if after, ok := strings.CutPrefix(h, "Bearer "); ok {
		return after
	}
	return h
}

// statusRecorder wraps an http.ResponseWriter to remember the status code
// written, so the request logger can report it. A handler that never
// calls WriteHeader has implicitly written 200.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// requestLogger emits one structured line per request — method, path,
// status, duration, and the client IP — to logger. Logs go to the
// injected logger (stderr by default): request telemetry is operational
// output, never mixed into an API response.
func requestLogger(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		logger.Info("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote_ip", clientIP(r),
		)
	})
}

// clientIP reports the IP to attribute a request to. Caddy terminates TLS
// in front of the server (Phase 6) and forwards the real client IP in
// X-Forwarded-For; that header wins when present, falling back to the
// direct peer address otherwise.
func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return fwd
	}
	return r.RemoteAddr
}
