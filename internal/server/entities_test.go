package server

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/cedar"
	"github.com/bensyverson/kura/internal/data"
	"github.com/bensyverson/kura/internal/gate"
	"github.com/bensyverson/kura/internal/identity"
	"github.com/bensyverson/kura/internal/manifest"
	"github.com/bensyverson/kura/internal/pii"
)

// entitiesServer builds a server over a two-entity manifest (patient and
// doctor), a record store seeded with three patients and one doctor, and
// a gate wired to the same authenticator. It returns the server plus an
// admin token (sees all PII) and a user token (high-sensitivity PII
// stays masked).
func entitiesServer(t *testing.T) (srv *Server, adminTok, userTok string) {
	t.Helper()
	m := &manifest.Manifest{
		Version: "1",
		Entities: []manifest.Entity{
			{Name: "patient", Fields: []manifest.Field{
				{Name: "full_name", Type: manifest.FieldString, PII: new(pii.CategoryPerson)},
				{Name: "account", Type: manifest.FieldString, PII: new(pii.CategoryAccountNumber)},
			}},
			{Name: "doctor", Fields: []manifest.Field{
				{Name: "full_name", Type: manifest.FieldString, PII: new(pii.CategoryPerson)},
			}},
		},
	}
	evaluator, err := cedar.NewEvaluator(cedar.DefaultPolicy(m))
	if err != nil {
		t.Fatalf("building evaluator: %v", err)
	}
	auth := identity.NewAuthenticator([]byte("test-signing-secret"))
	roles := gate.NewMapRoleResolver()
	roles.Assign("admin-svc", "admin")
	roles.Assign("user-svc", "user")
	detector := pii.NewFakeDetector().
		Register("Jane Doe", pii.CategoryPerson, 0.99).
		Register("John Roe", pii.CategoryPerson, 0.99).
		Register("Sam Poe", pii.CategoryPerson, 0.99).
		Register("Dr. Who", pii.CategoryPerson, 0.99).
		Register("ACCT-1", pii.CategoryAccountNumber, 0.99).
		Register("ACCT-2", pii.CategoryAccountNumber, 0.99).
		Register("ACCT-3", pii.CategoryAccountNumber, 0.99)

	store := data.NewMemStore()
	store.Put("patient", data.Record{ID: "p1", Fields: map[string]string{"full_name": "Jane Doe", "account": "ACCT-1"}})
	store.Put("patient", data.Record{ID: "p2", Fields: map[string]string{"full_name": "John Roe", "account": "ACCT-2"}})
	store.Put("patient", data.Record{ID: "p3", Fields: map[string]string{"full_name": "Sam Poe", "account": "ACCT-3"}})
	store.Put("doctor", data.Record{ID: "d1", Fields: map[string]string{"full_name": "Dr. Who"}})

	g, err := gate.New(auth, evaluator, roles, m, pii.NewScanner(detector), audit.NewRecorder(audit.NewMemStore()))
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}

	cfg, _ := testConfig(t, "127.0.0.1:0")
	cfg.Auth = auth
	cfg.Gate = g
	cfg.Records = store
	cfg.Writer = store
	srv, err = New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	mint := func(id string) string {
		tok, err := auth.Issue(identity.Principal{Type: identity.PrincipalService, ID: id}, time.Hour)
		if err != nil {
			t.Fatalf("issuing token for %s: %v", id, err)
		}
		return tok
	}
	return srv, mint("admin-svc"), mint("user-svc")
}

func doGet(t *testing.T, srv *Server, path, token string) *recorder {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := newRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

// f6d: a get and a list route exist for every entity the manifest
// declares — the routing tree is generated from the manifest, not
// hand-written per entity.
func TestEntityRoutesExistForEveryManifestEntity(t *testing.T) {
	srv, _, _ := entitiesServer(t)
	want := []string{
		"GET /api/patient", "GET /api/patient/{id}",
		"GET /api/doctor", "GET /api/doctor/{id}",
	}
	for _, pattern := range want {
		if _, ok := srv.apiRoutes[pattern]; !ok {
			t.Errorf("no data route registered for %q", pattern)
		}
	}
}

// OkE: a get response is masked per the requesting principal's policy —
// the admin sees the high-sensitivity account, the user does not.
func TestEntityGetIsMaskedPerPrincipal(t *testing.T) {
	srv, adminTok, userTok := entitiesServer(t)

	adminRec := doGet(t, srv, "/api/patient/p1", adminTok)
	if adminRec.status != http.StatusOK {
		t.Fatalf("admin get status = %d, want 200; body %s", adminRec.status, adminRec.body.String())
	}
	var adminFields map[string]string
	if err := json.Unmarshal(adminRec.body.Bytes(), &adminFields); err != nil {
		t.Fatalf("decoding admin body: %v", err)
	}
	if adminFields["account"] != "ACCT-1" {
		t.Errorf("admin account = %q, want plaintext ACCT-1", adminFields["account"])
	}

	userRec := doGet(t, srv, "/api/patient/p1", userTok)
	var userFields map[string]string
	if err := json.Unmarshal(userRec.body.Bytes(), &userFields); err != nil {
		t.Fatalf("decoding user body: %v", err)
	}
	if userFields["full_name"] != "Jane Doe" {
		t.Errorf("user full_name = %q, want plaintext", userFields["full_name"])
	}
	if userFields["account"] != gate.Redacted {
		t.Errorf("user account = %q, want %q", userFields["account"], gate.Redacted)
	}
}

// OkE + 7Ef: a list response is masked per principal and paginated, and
// with no query parameters it reports the gate's documented default
// page size.
func TestEntityListIsMaskedAndPaginatedByDefault(t *testing.T) {
	srv, _, userTok := entitiesServer(t)

	rec := doGet(t, srv, "/api/patient", userTok)
	if rec.status != http.StatusOK {
		t.Fatalf("list status = %d, want 200; body %s", rec.status, rec.body.String())
	}
	var resp listResponse
	if err := json.Unmarshal(rec.body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding list body %q: %v", rec.body.String(), err)
	}
	if len(resp.Records) != 3 {
		t.Fatalf("got %d records, want 3", len(resp.Records))
	}
	if resp.Limit != gate.DefaultPageSize {
		t.Errorf("list with no limit reported limit %d, want the default %d", resp.Limit, gate.DefaultPageSize)
	}
	if resp.Offset != 0 {
		t.Errorf("list reported offset %d, want 0", resp.Offset)
	}
	for _, r := range resp.Records {
		if r.Fields["account"] != gate.Redacted {
			t.Errorf("user list record %s account = %q, want redacted", r.ID, r.Fields["account"])
		}
		if r.Fields["full_name"] == gate.Redacted || r.Fields["full_name"] == "" {
			t.Errorf("user list record %s full_name = %q, want plaintext", r.ID, r.Fields["full_name"])
		}
	}
}

// 7Ef: the list endpoint honors limit and offset query parameters,
// reporting back the effective page it served.
func TestEntityListRespectsLimitAndOffset(t *testing.T) {
	srv, adminTok, _ := entitiesServer(t)

	rec := doGet(t, srv, "/api/patient?limit=1&offset=1", adminTok)
	if rec.status != http.StatusOK {
		t.Fatalf("list status = %d, want 200; body %s", rec.status, rec.body.String())
	}
	var resp listResponse
	if err := json.Unmarshal(rec.body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding list body: %v", err)
	}
	if len(resp.Records) != 1 || resp.Records[0].ID != "p2" {
		t.Errorf("list(limit 1, offset 1) records = %+v, want [p2]", resp.Records)
	}
	if resp.Limit != 1 || resp.Offset != 1 {
		t.Errorf("list reported limit/offset %d/%d, want 1/1", resp.Limit, resp.Offset)
	}
}

// A get for an id that does not exist is a 404 — a not-found, not a
// server error.
func TestEntityGetNotFound(t *testing.T) {
	srv, adminTok, _ := entitiesServer(t)
	rec := doGet(t, srv, "/api/patient/ghost", adminTok)
	if rec.status != http.StatusNotFound {
		t.Errorf("get missing record status = %d, want 404", rec.status)
	}
}

// A malformed pagination parameter is a client error — a 400, not a
// silent fallback that might hide a buggy caller.
func TestEntityListRejectsMalformedPagination(t *testing.T) {
	srv, adminTok, _ := entitiesServer(t)
	rec := doGet(t, srv, "/api/patient?limit=not-a-number", adminTok)
	if rec.status != http.StatusBadRequest {
		t.Errorf("list with malformed limit status = %d, want 400", rec.status)
	}
}
