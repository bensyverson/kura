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

// fakeEraser is an in-test Eraser: it records the ids it was asked to
// shred and returns a configurable count of destroyed DEKs. It is the
// default Eraser in testConfig and the recording spy in the erase tests.
type fakeEraser struct {
	erased   []string
	shredded int
	err      error
}

func (f *fakeEraser) Erase(_ context.Context, ids []string) (int, error) {
	if f.err != nil {
		return 0, f.err
	}
	f.erased = append(f.erased, ids...)
	return f.shredded, nil
}

// eraseServer builds a server whose erasure endpoint is backed by a
// recording fakeEraser, returned so a test can assert exactly which
// records were shredded. mint issues a token for a service principal
// holding the given roles.
func eraseServer(t *testing.T) (srv *Server, eraser *fakeEraser, mint func(id string, roles ...string) string) {
	t.Helper()
	m := &manifest.Manifest{
		Version:  "1",
		Entities: []manifest.Entity{{Name: "patient", Fields: []manifest.Field{{Name: "full_name", Type: manifest.FieldString}}}},
	}
	evaluator, err := cedar.NewEvaluator(cedar.DefaultPolicy(m))
	if err != nil {
		t.Fatalf("building evaluator: %v", err)
	}
	auth := identity.NewAuthenticator([]byte("test-signing-secret"))
	roles := gate.NewMapRoleResolver()
	g, err := gate.New(auth, evaluator, roles, m, pii.NewScanner(pii.NewFakeDetector()), audit.NewRecorder(audit.NewMemStore()))
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}

	cfg, _ := testConfig(t, "127.0.0.1:0")
	cfg.Auth = auth
	cfg.Gate = g
	eraser = &fakeEraser{}
	cfg.Eraser = eraser
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
	return srv, eraser, mint
}

// An admin can erase a set of records: the endpoint shreds exactly the
// named records through the gate and reports how many wrapped DEKs were
// destroyed.
func TestEraseEndpointShredsForAnAdmin(t *testing.T) {
	srv, eraser, mint := eraseServer(t)
	eraser.shredded = 5
	tok := mint("alice", "admin")

	rec := doPost(t, srv, "/api/erase", tok, `{"record_ids":["r1","r2"]}`)
	if rec.status != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.status, rec.body.String())
	}
	var got struct {
		Shredded int `json:"shredded"`
	}
	if err := json.Unmarshal(rec.body.Bytes(), &got); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if got.Shredded != 5 {
		t.Errorf("shredded = %d, want 5", got.Shredded)
	}
	if len(eraser.erased) != 2 || eraser.erased[0] != "r1" || eraser.erased[1] != "r2" {
		t.Errorf("eraser saw %v, want [r1 r2]", eraser.erased)
	}
}

// A non-admin is refused: the endpoint returns 403 and the eraser is
// never called — an unauthorized caller cannot forget a record.
func TestEraseEndpointForbiddenForNonAdmin(t *testing.T) {
	srv, eraser, mint := eraseServer(t)
	tok := mint("bob", "user")

	rec := doPost(t, srv, "/api/erase", tok, `{"record_ids":["r1"]}`)
	if rec.status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.status)
	}
	if len(eraser.erased) != 0 {
		t.Errorf("eraser was called for a non-admin: %v", eraser.erased)
	}
}

// An unauthenticated request never reaches the gate: requireAuth rejects
// it with 401 before any erasure logic runs.
func TestEraseEndpointRequiresAuth(t *testing.T) {
	srv, eraser, _ := eraseServer(t)

	rec := doPost(t, srv, "/api/erase", "", `{"record_ids":["r1"]}`)
	if rec.status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.status)
	}
	if len(eraser.erased) != 0 {
		t.Errorf("eraser was called without authentication: %v", eraser.erased)
	}
}
