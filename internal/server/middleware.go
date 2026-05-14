package server

import (
	"log/slog"
	"net/http"
	"time"
)

// requireAuth rejects any request that carries no credential before the
// wrapped handler runs — the "every route authenticated before business
// logic" rule. The skeleton checks only for the presence of an
// Authorization header; resolving that credential to a Cedar principal,
// and rejecting an invalid one, is the next task (server-auth).
func requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
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
