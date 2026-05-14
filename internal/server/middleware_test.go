package server

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// recorder is a minimal http.ResponseWriter that remembers the status code
// the handler wrote.
type recorder struct {
	status int
	body   bytes.Buffer
}

func newRecorder() *recorder { return &recorder{status: http.StatusOK} }

func (r *recorder) Header() http.Header         { return http.Header{} }
func (r *recorder) Write(b []byte) (int, error) { return r.body.Write(b) }
func (r *recorder) WriteHeader(code int)        { r.status = code }

// requireAuth must reject a request with no credential and must not run
// the wrapped handler — authentication happens before business logic.
func TestRequireAuthRejectsBeforeHandlerRuns(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })

	req, _ := http.NewRequest(http.MethodGet, "/api/people/89", nil)
	rec := newRecorder()
	requireAuth(next).ServeHTTP(rec, req)

	if called {
		t.Error("wrapped handler ran for an unauthenticated request")
	}
	if rec.status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.status)
	}
}

// A request carrying a credential reaches the wrapped handler.
func TestRequireAuthPassesCredentialedRequest(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })

	req, _ := http.NewRequest(http.MethodGet, "/api/people/89", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	rec := newRecorder()
	requireAuth(next).ServeHTTP(rec, req)

	if !called {
		t.Error("wrapped handler did not run for a credentialed request")
	}
}

// The request logger writes one structured line per request to the
// configured logger, carrying method, path, and status.
func TestRequestLoggerLogsStructuredLine(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	requestLogger(logger, next).ServeHTTP(httptest.NewRecorder(), req)

	line := buf.String()
	for _, want := range []string{"GET", "/healthz", "418"} {
		if !strings.Contains(line, want) {
			t.Errorf("request log line missing %q: %s", want, line)
		}
	}
}
