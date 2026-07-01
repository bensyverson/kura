package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/cedar"
	"github.com/bensyverson/kura/internal/data"
	"github.com/bensyverson/kura/internal/gate"
	"github.com/bensyverson/kura/internal/identity"
	"github.com/bensyverson/kura/internal/jobs"
	"github.com/bensyverson/kura/internal/manifest"
	"github.com/bensyverson/kura/internal/pii"
	"github.com/bensyverson/kura/internal/review"
)

// testConfig returns a complete, wired Config for the given bind address,
// backed by in-memory fakes. It also returns the Authenticator so a test
// can mint tokens the server will accept. The Gate is wired over the
// same Authenticator, so a token the server accepts the gate accepts too.
func testConfig(t *testing.T, addr string) (Config, *identity.Authenticator) {
	t.Helper()
	auth := identity.NewAuthenticator([]byte("test-signing-secret"))
	m := &manifest.Manifest{
		Version:  "1",
		Entities: []manifest.Entity{{Name: "patient", Fields: []manifest.Field{{Name: "id", Type: manifest.FieldString}}}},
	}
	evaluator, err := cedar.NewEvaluator(cedar.DefaultPolicy(m))
	if err != nil {
		t.Fatalf("building evaluator: %v", err)
	}
	store := audit.NewMemStore()
	recorder := audit.NewRecorder(store)
	g, err := gate.New(auth, evaluator, gate.NewMapRoleResolver(), m, pii.NewScanner(pii.NewFakeDetector()), recorder)
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	jobsMgr := jobs.NewManager(jobs.NewMemStore()).WithIdleBackoff(5 * time.Millisecond)
	records := data.NewMemStore()
	return Config{
		Addr:     addr,
		Logger:   discardLogger(),
		Auth:     auth,
		Recorder: recorder,
		Google:   &fakeGoogle{consentURL: "https://accounts.google.example/auth"},
		Trust:    testTrust(),
		TokenTTL: time.Hour,
		Gate:     g,
		Records:  records,
		Writer:   records,
		Edges:    records,
		Eraser:   &fakeEraser{},
		Users:    data.NewMemUserStore(),
		IdP:      identity.NewFakeDirectory(),
		Audit:    store,
		Jobs:     jobsMgr,
		Reviews:  review.NewMemStore(),
	}, auth
}

// kura serve must start, bind a real socket, serve its health endpoints,
// and shut down gracefully when its context is cancelled.
func TestServerServesHealthAndShutsDownGracefully(t *testing.T) {
	cfg, _ := testConfig(t, "127.0.0.1:0")
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- srv.Run(ctx) }()

	select {
	case <-srv.Ready():
	case err := <-errc:
		t.Fatalf("server exited before becoming ready: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("server never became ready")
	}

	for _, path := range []string{"/healthz", "/readyz"} {
		resp, err := http.Get("http://" + srv.BoundAddr() + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s: status = %d, want 200", path, resp.StatusCode)
		}
	}

	cancel()
	select {
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("Run returned error on graceful shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not shut down within timeout after context cancel")
	}
}

// New requires its enforcement collaborators — a server that cannot
// resolve a token or record an audit event must not come into existence.
func TestNewRequiresEnforcementDependencies(t *testing.T) {
	cfg, _ := testConfig(t, "127.0.0.1:0")
	cfg.Auth = nil
	if _, err := New(cfg); err == nil {
		t.Error("New returned no error when Auth was nil")
	}
}

// An unauthenticated request to a data route must be rejected before any
// business-logic handler runs.
func TestUnauthenticatedDataRouteRejectedBeforeBusinessLogic(t *testing.T) {
	cfg, _ := testConfig(t, "127.0.0.1:0")
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, "/api/people/89", nil)
	rec := newRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for unauthenticated /api request", rec.status)
	}
}

// A request carrying a valid token is allowed past the auth gate (the
// skeleton has no data handlers yet, so it 404s rather than 401s).
func TestValidTokenPassesAuthGate(t *testing.T) {
	cfg, auth := testConfig(t, "127.0.0.1:0")
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	token, err := auth.Issue(identity.Principal{
		Type:   identity.PrincipalConsultant,
		ID:     "alex@examplefirm.com",
		Email:  "alex@examplefirm.com",
		Tenant: "examplefirm.com",
	}, time.Hour)
	if err != nil {
		t.Fatalf("issuing token: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, "/api/people/89", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := newRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.status == http.StatusUnauthorized {
		t.Errorf("request with a valid token was rejected by the auth gate (status %d)", rec.status)
	}
}
