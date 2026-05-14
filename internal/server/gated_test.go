package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/cedar"
	"github.com/bensyverson/kura/internal/gate"
	"github.com/bensyverson/kura/internal/identity"
	"github.com/bensyverson/kura/internal/manifest"
	"github.com/bensyverson/kura/internal/pii"
)

// gateFixture builds a real Gate over in-memory fakes, returning the gate,
// the audit store behind it (so a test can see what was recorded), the
// authenticator, and a valid token for a principal holding the "admin"
// role on the test manifest.
func gateFixture(t *testing.T) (*gate.Gate, *audit.MemStore, *identity.Authenticator, string) {
	t.Helper()
	m := &manifest.Manifest{
		Version: "1",
		Entities: []manifest.Entity{{
			Name: "patient",
			Fields: []manifest.Field{
				{Name: "full_name", Type: manifest.FieldString, PII: new(pii.CategoryPerson)},
				{Name: "account", Type: manifest.FieldString, PII: new(pii.CategoryAccountNumber)},
			},
		}},
	}
	evaluator, err := cedar.NewEvaluator(cedar.DefaultPolicy(m))
	if err != nil {
		t.Fatalf("building evaluator: %v", err)
	}
	auth := identity.NewAuthenticator([]byte("test-signing-secret"))
	roles := gate.NewMapRoleResolver()
	roles.Assign("svc-1", "admin")
	store := audit.NewMemStore()
	detector := pii.NewFakeDetector().
		Register("Jane Doe", pii.CategoryPerson, 0.99).
		Register("ACCT-555", pii.CategoryAccountNumber, 0.99)

	g, err := gate.New(auth, evaluator, roles, m, pii.NewScanner(detector), audit.NewRecorder(store))
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	tok, err := auth.Issue(identity.Principal{Type: identity.PrincipalService, ID: "svc-1"}, time.Hour)
	if err != nil {
		t.Fatalf("issuing token: %v", err)
	}
	return g, store, auth, tok
}

// patientBinding is a stand-in data-route binding: it names the patient
// entity and supplies a fixed record. The real data endpoints (a later
// task) supply bindings of exactly this shape — they describe the gate
// request, they never write the response themselves.
func patientBinding(r *http.Request, p identity.Principal) (gate.AccessRequest, gate.Fetcher, error) {
	req := gate.AccessRequest{
		Token:      bearerToken(r),
		Action:     cedar.ActionRead,
		Entity:     "patient",
		ResourceID: "p1",
	}
	fetch := func(_ context.Context) (map[string]string, error) {
		return map[string]string{"full_name": "Jane Doe", "account": "ACCT-555"}, nil
	}
	return req, fetch, nil
}

// QIB: a data route registered through registerData serves its response
// only by going through the gate — so the response carries a
// corresponding audit Access event, and that event carries the real
// client IP the middleware recorded.
func TestGatedRouteEmitsAuditEvent(t *testing.T) {
	g, store, auth, tok := gateFixture(t)

	cfg, _ := testConfig(t, "127.0.0.1:0")
	cfg.Auth = auth
	cfg.Gate = g
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv.registerData("GET /api/patients/{id}", patientBinding)

	req, _ := http.NewRequest(http.MethodGet, "/api/patients/p1", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	rec := newRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.status != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.status, rec.body.String())
	}
	var fields map[string]string
	if err := json.Unmarshal(rec.body.Bytes(), &fields); err != nil {
		t.Fatalf("decoding response body %q: %v", rec.body.String(), err)
	}
	if fields["full_name"] != "Jane Doe" {
		t.Errorf("full_name = %q, want %q", fields["full_name"], "Jane Doe")
	}

	events, _ := store.Query(context.Background(), audit.Filter{})
	var access *audit.Event
	for i := range events {
		if events[i].Kind == audit.KindAccess {
			access = &events[i]
		}
	}
	if access == nil {
		t.Fatalf("data response carried no audit Access event; events = %+v", events)
	}
	if access.Resource.Entity != "patient" || access.Resource.ID != "p1" {
		t.Errorf("access event resource = %+v, want patient/p1", access.Resource)
	}
	if access.IP != "203.0.113.7" {
		t.Errorf("access event IP = %q, want the forwarded client IP %q", access.IP, "203.0.113.7")
	}
}

// RLg: the architectural guard — every route mounted under /api/ goes
// through the core gate. A route that bypasses the gate cannot even be
// registered: apiRoutes is a map of gatedRoute, and a raw handler does
// not satisfy gatedRoute.
func TestEveryDataRouteIsGated(t *testing.T) {
	srv, _, _ := entitiesServer(t)
	if len(srv.apiRoutes) == 0 {
		t.Fatal("no data routes registered to check")
	}
	for pattern, h := range srv.apiRoutes {
		switch h.(type) {
		case *gatedHandler, *gatedListHandler, *adminHandler:
			// ok — a thin wrapper that delegates to the gate
		default:
			t.Errorf("api route %q is %T, not a gated handler — it could serve a response that bypassed the gate", pattern, h)
		}
	}

	// The guard has teeth: a raw http.Handler does not satisfy
	// gatedRoute, so it cannot be stored as a data route at all. If this
	// ever stops holding, the map's value type has been loosened and the
	// compile-time guarantee is gone.
	var raw http.Handler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	if _, ok := raw.(gatedRoute); ok {
		t.Error("a raw http.Handler satisfied gatedRoute — the gate boundary is not closed")
	}
}
