package server

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/identity"
)

// recorder is a minimal http.ResponseWriter that remembers the status
// code the handler wrote.
type recorder struct {
	status int
	body   bytes.Buffer
}

func newRecorder() *recorder { return &recorder{status: http.StatusOK} }

func (r *recorder) Header() http.Header         { return http.Header{} }
func (r *recorder) Write(b []byte) (int, error) { return r.body.Write(b) }
func (r *recorder) WriteHeader(code int)        { r.status = code }

// authFixture returns an Authenticator and an audit store for exercising
// requireAuth, plus a freshly minted valid Consultant token.
func authFixture(t *testing.T) (*identity.Authenticator, *audit.MemStore, string) {
	t.Helper()
	auth := identity.NewAuthenticator([]byte("test-signing-secret"))
	store := audit.NewMemStore()
	token, err := auth.Issue(identity.Principal{
		Type:   identity.PrincipalConsultant,
		ID:     "alex@examplefirm.com",
		Email:  "alex@examplefirm.com",
		Tenant: "examplefirm.com",
	}, time.Hour)
	if err != nil {
		t.Fatalf("issuing test token: %v", err)
	}
	return auth, store, token
}

// requireAuth must reject a request with no credential, must not run the
// wrapped handler, and must record the failed authentication — a
// rejected credential is an audit-worthy event.
func TestRequireAuthRejectsBeforeHandlerRuns(t *testing.T) {
	auth, store, _ := authFixture(t)
	rec := audit.NewRecorder(store)
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })

	req := httptest.NewRequest(http.MethodGet, "/api/people/89", nil)
	w := newRecorder()
	requireAuth(auth, rec, discardLogger(), next).ServeHTTP(w, req)

	if called {
		t.Error("wrapped handler ran for an unauthenticated request")
	}
	if w.status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.status)
	}
	events, _ := store.Query(context.Background(), audit.Filter{})
	if len(events) != 1 || events[0].Kind != audit.KindAuthentication || events[0].Outcome != audit.OutcomeDenied {
		t.Errorf("expected one denied authentication event, got %+v", events)
	}
}

// A valid token resolves to the correct Cedar principal, which is made
// available to the wrapped handler through the request context.
func TestRequireAuthResolvesValidTokenToPrincipal(t *testing.T) {
	auth, store, token := authFixture(t)
	rec := audit.NewRecorder(store)

	var got identity.Principal
	var ok bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok = principalFromContext(r.Context())
	})
	req := httptest.NewRequest(http.MethodGet, "/api/people/89", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := newRecorder()
	requireAuth(auth, rec, discardLogger(), next).ServeHTTP(w, req)

	if !ok {
		t.Fatal("wrapped handler did not receive a principal in context")
	}
	if got.Type != identity.PrincipalConsultant || got.Email != "alex@examplefirm.com" {
		t.Errorf("resolved the wrong principal: %+v", got)
	}
}

// An expired token is rejected — the wrapped handler never runs.
func TestRequireAuthRejectsExpiredToken(t *testing.T) {
	auth, store, _ := authFixture(t)
	rec := audit.NewRecorder(store)
	expired, err := auth.Issue(identity.Principal{
		Type:   identity.PrincipalConsultant,
		ID:     "alex@examplefirm.com",
		Email:  "alex@examplefirm.com",
		Tenant: "examplefirm.com",
	}, -time.Minute)
	if err != nil {
		t.Fatalf("issuing expired token: %v", err)
	}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	req := httptest.NewRequest(http.MethodGet, "/api/people/89", nil)
	req.Header.Set("Authorization", "Bearer "+expired)
	w := newRecorder()
	requireAuth(auth, rec, discardLogger(), next).ServeHTTP(w, req)

	if called {
		t.Error("wrapped handler ran for an expired token")
	}
	if w.status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for an expired token", w.status)
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
