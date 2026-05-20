package server

import (
	"encoding/json"
	"net/http"
	"strings"
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

// ingestServer builds a server over a one-entity manifest whose record
// store is shared between reads and writes, so an ingested record can be
// read back. It returns the server and a mint helper that issues a token
// for a service principal holding the given roles.
func ingestServer(t *testing.T) (srv *Server, mint func(id string, roles ...string) string) {
	t.Helper()
	m := &manifest.Manifest{
		Version: "1",
		Entities: []manifest.Entity{{
			Name: "patient",
			Fields: []manifest.Field{
				{Name: "full_name", Type: manifest.FieldString, PII: new(pii.CategoryPerson)},
				{Name: "notes", Type: manifest.FieldText},
			},
		}},
	}
	evaluator, err := cedar.NewEvaluator(cedar.DefaultPolicy(m))
	if err != nil {
		t.Fatalf("building evaluator: %v", err)
	}
	auth := identity.NewAuthenticator([]byte("test-signing-secret"))
	roles := gate.NewMapRoleResolver()
	store := data.NewMemStore()
	g, err := gate.New(auth, evaluator, roles, m, pii.NewScanner(pii.NewFakeDetector()), audit.NewRecorder(audit.NewMemStore()))
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

	mint = func(id string, rs ...string) string {
		roles.Assign(id, rs...)
		tok, err := auth.Issue(identity.Principal{Type: identity.PrincipalService, ID: id}, time.Hour)
		if err != nil {
			t.Fatalf("issuing token for %s: %v", id, err)
		}
		return tok
	}
	return srv, mint
}

func doPost(t *testing.T, srv *Server, path, token, body string) *recorder {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := newRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

// A POST ingestion route is generated for every manifest entity, just like
// the get and list routes.
func TestIngestRouteExistsForEveryManifestEntity(t *testing.T) {
	srv, _ := ingestServer(t)
	if _, ok := srv.apiRoutes["POST /api/patient"]; !ok {
		t.Error("no ingestion route registered for POST /api/patient")
	}
}

// POST /api/{entity} ingests a record through the gate and returns its new
// id; the record is then readable through the get route — a full HTTP
// round-trip.
func TestIngestEndpointCreatesAndReadsBackRecord(t *testing.T) {
	srv, mint := ingestServer(t)
	tok := mint("admin-svc", "admin")

	rec := doPost(t, srv, "/api/patient", tok, `{"full_name":"New Person"}`)
	if rec.status != http.StatusCreated {
		t.Fatalf("POST status = %d, want 201; body %s", rec.status, rec.body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.body.Bytes(), &created); err != nil {
		t.Fatalf("decoding POST body: %v", err)
	}
	if created.ID == "" {
		t.Fatal("POST returned an empty id")
	}

	got := doGet(t, srv, "/api/patient/"+created.ID, tok)
	if got.status != http.StatusOK {
		t.Fatalf("GET status = %d, want 200; body %s", got.status, got.body.String())
	}
	var fields map[string]string
	if err := json.Unmarshal(got.body.Bytes(), &fields); err != nil {
		t.Fatalf("decoding GET body: %v", err)
	}
	if fields["full_name"] != "New Person" {
		t.Errorf("round-tripped full_name = %q, want New Person", fields["full_name"])
	}
}

// A principal whose role cannot create is forbidden — the endpoint answers
// 403, the gate's denial surfaced.
func TestIngestEndpointForbidsRoleThatCannotCreate(t *testing.T) {
	srv, mint := ingestServer(t)
	tok := mint("noroles-svc") // no roles: no create grant

	rec := doPost(t, srv, "/api/patient", tok, `{"full_name":"New Person"}`)
	if rec.status != http.StatusForbidden {
		t.Errorf("POST status = %d, want 403; body %s", rec.status, rec.body.String())
	}
}

// An unauthenticated POST is rejected before reaching the gate.
func TestIngestEndpointRequiresAuth(t *testing.T) {
	srv, _ := ingestServer(t)
	rec := doPost(t, srv, "/api/patient", "", `{"full_name":"New Person"}`)
	if rec.status != http.StatusUnauthorized {
		t.Errorf("POST status = %d, want 401; body %s", rec.status, rec.body.String())
	}
}

// A malformed JSON body is a client error — 400, not a 500.
func TestIngestEndpointRejectsMalformedBody(t *testing.T) {
	srv, mint := ingestServer(t)
	tok := mint("admin-svc", "admin")
	rec := doPost(t, srv, "/api/patient", tok, `{not json`)
	if rec.status != http.StatusBadRequest {
		t.Errorf("POST status = %d, want 400; body %s", rec.status, rec.body.String())
	}
}

// A field the manifest does not declare is refused — the gate's
// ErrUnknownField surfaces as a 400 (a malformed request for this schema),
// and nothing is written.
func TestIngestEndpointRejectsUnknownField(t *testing.T) {
	srv, mint := ingestServer(t)
	tok := mint("admin-svc", "admin")
	rec := doPost(t, srv, "/api/patient", tok, `{"full_name":"New Person","ssn":"123-45-6789"}`)
	if rec.status != http.StatusBadRequest {
		t.Errorf("POST status = %d, want 400; body %s", rec.status, rec.body.String())
	}
}
