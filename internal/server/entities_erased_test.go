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

// erasedEntityServer builds a server over a one-entity manifest whose sole
// record has a crypto-shredded field: "account" is named in the record's
// Erased list and absent from its Fields, exactly as the store reports a
// field whose per-value DEK has been destroyed. It returns the server and
// an admin token that would see the account in plaintext if it were still
// decryptable — so a masked value can never be mistaken for an erased one.
func erasedEntityServer(t *testing.T) (srv *Server, adminTok string) {
	t.Helper()
	m := &manifest.Manifest{
		Version: "1",
		Entities: []manifest.Entity{
			{Name: "patient", Fields: []manifest.Field{
				{Name: "full_name", Type: manifest.FieldString, PII: new(pii.CategoryPerson)},
				{Name: "account", Type: manifest.FieldString, PII: new(pii.CategoryAccountNumber)},
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
	detector := pii.NewFakeDetector().Register("Ada Lovelace", pii.CategoryPerson, 0.99)

	store := data.NewMemStore()
	// The account field's DEK was shredded: no value in Fields, named in Erased.
	store.Put("patient", data.Record{
		ID:     "p1",
		Fields: map[string]string{"full_name": "Ada Lovelace"},
		Erased: []string{"account"},
	})

	g, err := gate.New(auth, evaluator, roles, m, pii.NewScanner(detector), audit.NewRecorder(audit.NewMemStore()))
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
	tok, err := auth.Issue(identity.Principal{Type: identity.PrincipalService, ID: "admin-svc"}, time.Hour)
	if err != nil {
		t.Fatalf("issuing token: %v", err)
	}
	return srv, tok
}

// hYT (single get): a get of a record with a shredded-DEK field is a normal
// 200 read whose body names the field in "erased" and omits it from
// "fields" — never the ciphertext, never a value, never an error.
func TestEntityGetSurfacesErasedField(t *testing.T) {
	srv, adminTok := erasedEntityServer(t)

	rec := doGet(t, srv, "/api/patient/p1", adminTok)
	if rec.status != http.StatusOK {
		t.Fatalf("get of an erased record status = %d, want 200; body %s", rec.status, rec.body.String())
	}
	var got struct {
		Fields map[string]string `json:"fields"`
		Erased []string          `json:"erased"`
	}
	if err := json.Unmarshal(rec.body.Bytes(), &got); err != nil {
		t.Fatalf("decoding body %q: %v", rec.body.String(), err)
	}
	if len(got.Erased) != 1 || got.Erased[0] != "account" {
		t.Errorf("erased = %v, want [account]", got.Erased)
	}
	if _, present := got.Fields["account"]; present {
		t.Errorf("erased field surfaced a value in fields: %q", got.Fields["account"])
	}
	if got.Fields["full_name"] != "Ada Lovelace" {
		t.Errorf("full_name = %q, want plaintext", got.Fields["full_name"])
	}
}

// hYT (list): a list page carries each record's erased field names, so a
// listing of records with erased fields stays a normal read.
func TestEntityListSurfacesErasedField(t *testing.T) {
	srv, adminTok := erasedEntityServer(t)

	rec := doGet(t, srv, "/api/patient", adminTok)
	if rec.status != http.StatusOK {
		t.Fatalf("list status = %d, want 200; body %s", rec.status, rec.body.String())
	}
	var resp struct {
		Records []struct {
			ID     string            `json:"id"`
			Fields map[string]string `json:"fields"`
			Erased []string          `json:"erased"`
		} `json:"records"`
	}
	if err := json.Unmarshal(rec.body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding list body %q: %v", rec.body.String(), err)
	}
	if len(resp.Records) != 1 {
		t.Fatalf("got %d records, want 1", len(resp.Records))
	}
	if len(resp.Records[0].Erased) != 1 || resp.Records[0].Erased[0] != "account" {
		t.Errorf("record erased = %v, want [account]", resp.Records[0].Erased)
	}
	if _, present := resp.Records[0].Fields["account"]; present {
		t.Errorf("erased field surfaced a value in list fields: %q", resp.Records[0].Fields["account"])
	}
}
