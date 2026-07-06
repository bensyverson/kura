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
		Entities: []manifest.Entity{
			{
				Name:   "provider",
				Fields: []manifest.Field{{Name: "name", Type: manifest.FieldString}},
			},
			{
				Name: "patient",
				Fields: []manifest.Field{
					{Name: "full_name", Type: manifest.FieldString, PII: new(pii.CategoryPerson)},
					{Name: "notes", Type: manifest.FieldText},
				},
				Relationships: []manifest.Relationship{
					{Name: "primary_provider", Kind: manifest.RelationshipOne, Target: "provider"},
					{Name: "care_team", Kind: manifest.RelationshipMany, Target: "provider"},
				},
			},
		},
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
	cfg.Edges = store
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

	rec := doPost(t, srv, "/api/patient", tok, `{"fields":{"full_name":"New Person"}}`)
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
	var resp recordResponse
	if err := json.Unmarshal(got.body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding GET body: %v", err)
	}
	if resp.Fields["full_name"] != "New Person" {
		t.Errorf("round-tripped full_name = %q, want New Person", resp.Fields["full_name"])
	}
}

// postAndID POSTs a body to an entity's ingestion route and returns the new
// record's id, failing the test on a non-201.
func postAndID(t *testing.T, srv *Server, entity, tok, body string) string {
	t.Helper()
	rec := doPost(t, srv, "/api/"+entity, tok, body)
	if rec.status != http.StatusCreated {
		t.Fatalf("POST /api/%s status = %d, want 201; body %s", entity, rec.status, rec.body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.body.Bytes(), &created); err != nil {
		t.Fatalf("decoding POST body: %v", err)
	}
	return created.ID
}

// edgeRow mirrors one edge in the edges endpoint's JSON response.
type edgeRow struct {
	Relationship string `json:"relationship"`
	SourceID     string `json:"source_id"`
	SourceSeq    int64  `json:"source_seq"`
	TargetID     string `json:"target_id"`
}

// getEdges GETs a record's edges in the given direction, returning the rows.
func getEdges(t *testing.T, srv *Server, entity, id, tok, direction string) []edgeRow {
	t.Helper()
	got := doGet(t, srv, "/api/"+entity+"/"+id+"/edges?direction="+direction, tok)
	if got.status != http.StatusOK {
		t.Fatalf("GET edges status = %d, want 200; body %s", got.status, got.body.String())
	}
	var out struct {
		Edges []edgeRow `json:"edges"`
	}
	if err := json.Unmarshal(got.body.Bytes(), &out); err != nil {
		t.Fatalf("decoding edges body: %v", err)
	}
	return out.Edges
}

// A record can be created with relationships in one POST, and the edges read
// back through the edges endpoint — outgoing from the source and incoming to
// the target. This is the create-with-relationships round-trip end to end.
func TestIngestEndpointCreatesRecordWithRelationship(t *testing.T) {
	srv, mint := ingestServer(t)
	tok := mint("admin-svc", "admin")

	provID := postAndID(t, srv, "provider", tok, `{"fields":{"name":"Dr. X"}}`)
	patID := postAndID(t, srv, "patient", tok,
		`{"fields":{"full_name":"Jane"},"relationships":{"primary_provider":["`+provID+`"]}}`)

	out := getEdges(t, srv, "patient", patID, tok, "out")
	if len(out) != 1 || out[0].Relationship != "primary_provider" || out[0].TargetID != provID {
		t.Fatalf("outgoing edges = %+v, want one primary_provider edge to %s", out, provID)
	}
	if out[0].SourceID != patID {
		t.Errorf("outgoing edge SourceID = %q, want %q", out[0].SourceID, patID)
	}

	in := getEdges(t, srv, "provider", provID, tok, "in")
	if len(in) != 1 || in[0].SourceID != patID || in[0].TargetID != provID {
		t.Fatalf("incoming edges = %+v, want one edge from %s to %s", in, patID, provID)
	}
}

// A relationship to a target that does not exist is rejected at ingest — the
// gate's ErrEdgeTarget surfaces as a 400.
func TestIngestEndpointRejectsMissingRelationshipTarget(t *testing.T) {
	srv, mint := ingestServer(t)
	tok := mint("admin-svc", "admin")
	rec := doPost(t, srv, "/api/patient", tok,
		`{"fields":{"full_name":"Jane"},"relationships":{"primary_provider":["ghost"]}}`)
	if rec.status != http.StatusBadRequest {
		t.Errorf("POST with a missing relationship target: status = %d, want 400; body %s", rec.status, rec.body.String())
	}
}

// The edges endpoint requires an explicit direction — an omitted or invalid
// direction is a 400, never an implied default.
func TestEdgesEndpointRequiresDirection(t *testing.T) {
	srv, mint := ingestServer(t)
	tok := mint("admin-svc", "admin")
	id := postAndID(t, srv, "provider", tok, `{"fields":{"name":"Dr. X"}}`)

	if got := doGet(t, srv, "/api/provider/"+id+"/edges", tok); got.status != http.StatusBadRequest {
		t.Errorf("GET edges with no direction: status = %d, want 400", got.status)
	}
	if got := doGet(t, srv, "/api/provider/"+id+"/edges?direction=sideways", tok); got.status != http.StatusBadRequest {
		t.Errorf("GET edges with an invalid direction: status = %d, want 400", got.status)
	}
}

// A principal whose role cannot create is forbidden — the endpoint answers
// 403, the gate's denial surfaced.
func TestIngestEndpointForbidsRoleThatCannotCreate(t *testing.T) {
	srv, mint := ingestServer(t)
	tok := mint("noroles-svc") // no roles: no create grant

	rec := doPost(t, srv, "/api/patient", tok, `{"fields":{"full_name":"New Person"}}`)
	if rec.status != http.StatusForbidden {
		t.Errorf("POST status = %d, want 403; body %s", rec.status, rec.body.String())
	}
}

// An unauthenticated POST is rejected before reaching the gate.
func TestIngestEndpointRequiresAuth(t *testing.T) {
	srv, _ := ingestServer(t)
	rec := doPost(t, srv, "/api/patient", "", `{"fields":{"full_name":"New Person"}}`)
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
	rec := doPost(t, srv, "/api/patient", tok, `{"fields":{"full_name":"New Person","ssn":"123-45-6789"}}`)
	if rec.status != http.StatusBadRequest {
		t.Errorf("POST status = %d, want 400; body %s", rec.status, rec.body.String())
	}
}
