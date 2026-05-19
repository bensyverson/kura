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

// overviewServer builds a server wired like adminServer but exposing the
// record store and audit store, so a test can seed records and events and
// assert the overview's counts and recent activity. The manifest carries
// two entities so the per-entity breakdown is non-trivial. The seeded
// admin and plain user are marked active in the IdP, so the only IdP
// mismatch in a test is one the test creates deliberately.
func overviewServer(t *testing.T) (srv *Server, records *data.MemStore, auditStore *audit.MemStore, idp *identity.FakeDirectory, users *data.MemUserStore, adminTok, userTok string) {
	t.Helper()
	m := &manifest.Manifest{
		Version: "1",
		Entities: []manifest.Entity{
			{Name: "patient", Fields: []manifest.Field{{Name: "full_name", Type: manifest.FieldString, PII: new(pii.CategoryPerson)}}},
			{Name: "doctor", Fields: []manifest.Field{{Name: "full_name", Type: manifest.FieldString, PII: new(pii.CategoryPerson)}}},
		},
	}
	evaluator, err := cedar.NewEvaluator(cedar.DefaultPolicy(m))
	if err != nil {
		t.Fatalf("building evaluator: %v", err)
	}
	auth := identity.NewAuthenticator([]byte("test-signing-secret"))
	users = data.NewMemUserStore()
	idp = identity.NewFakeDirectory()
	for email, role := range map[string]string{
		"admin@client.com": "admin",
		"user@client.com":  "user",
	} {
		if err := users.AddUser(t.Context(), email); err != nil {
			t.Fatalf("seeding user %s: %v", email, err)
		}
		if err := users.AssignRoles(t.Context(), email, role); err != nil {
			t.Fatalf("seeding role for %s: %v", email, err)
		}
		idp.Set(email, identity.AccountActive)
	}

	// One audit store backs both the gate's recorder and the read seam, as
	// the real deployment wires it — so an event the gate writes is an
	// event the overview can read.
	auditStore = audit.NewMemStore()
	recorder := audit.NewRecorder(auditStore)
	g, err := gate.New(auth, evaluator, users, m, pii.NewScanner(pii.NewFakeDetector()), recorder)
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}

	cfg, _ := testConfig(t, "127.0.0.1:0")
	cfg.Auth = auth
	cfg.Gate = g
	cfg.Users = users
	cfg.IdP = idp
	records = data.NewMemStore()
	cfg.Records = records
	cfg.Recorder = recorder
	cfg.Audit = auditStore
	srv, err = New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	mint := func(email string, typ identity.PrincipalType) string {
		tok, err := auth.Issue(identity.Principal{Type: typ, ID: email, Email: email, Tenant: "client.com"}, time.Hour)
		if err != nil {
			t.Fatalf("issuing token for %s: %v", email, err)
		}
		return tok
	}
	return srv, records, auditStore, idp, users,
		mint("admin@client.com", identity.PrincipalAdmin),
		mint("user@client.com", identity.PrincipalUser)
}

// The overview is the dashboard's landscape briefing in one read: system
// status, deployment tier, record and user counts, and a needs-attention
// panel. It is an AdminReview read, so it is authorized and audited like
// every other admin endpoint.
func TestOverviewReportsStatusTierCountsAndAttention(t *testing.T) {
	srv, records, _, idp, users, adminTok, _ := overviewServer(t)

	records.Put("patient", data.Record{ID: "p1", Fields: map[string]string{"full_name": "Jane Doe"}})
	records.Put("patient", data.Record{ID: "p2", Fields: map[string]string{"full_name": "John Roe"}})
	records.Put("doctor", data.Record{ID: "d1", Fields: map[string]string{"full_name": "Dr. Who"}})

	// A user who still holds a role but whose IdP account is suspended is
	// the deliberate needs-attention item.
	if err := users.AddUser(t.Context(), "suspended@client.com"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if err := users.AssignRoles(t.Context(), "suspended@client.com", "user"); err != nil {
		t.Fatalf("AssignRoles: %v", err)
	}
	idp.Set("suspended@client.com", identity.AccountSuspended)

	rec := doReq(t, srv, http.MethodGet, "/api/overview", adminTok, "")
	if rec.status != http.StatusOK {
		t.Fatalf("GET /api/overview as admin: status = %d, want 200; body %s", rec.status, rec.body.String())
	}

	var got struct {
		Status string `json:"status"`
		Tier   string `json:"tier"`
		Counts struct {
			Entities int `json:"entities"`
			Records  int `json:"records"`
			Users    int `json:"users"`
			ByEntity []struct {
				Entity string `json:"entity"`
				Count  int    `json:"count"`
			} `json:"by_entity"`
		} `json:"counts"`
		NeedsAttention struct {
			IdPMismatches []data.IdPMismatch `json:"idp_mismatches"`
			Anomalies     []string           `json:"anomalies"`
		} `json:"needs_attention"`
	}
	if err := json.Unmarshal(rec.body.Bytes(), &got); err != nil {
		t.Fatalf("decoding overview: %v; body %s", err, rec.body.String())
	}

	if got.Status == "" {
		t.Error("overview reported no system status")
	}
	if got.Tier == "" {
		t.Error("overview reported no deployment tier")
	}
	if got.Counts.Entities != 2 {
		t.Errorf("entities = %d, want 2", got.Counts.Entities)
	}
	if got.Counts.Records != 3 {
		t.Errorf("total records = %d, want 3", got.Counts.Records)
	}
	if got.Counts.Users != 3 {
		t.Errorf("users = %d, want 3 (admin, user, suspended)", got.Counts.Users)
	}
	byEntity := map[string]int{}
	for _, e := range got.Counts.ByEntity {
		byEntity[e.Entity] = e.Count
	}
	if byEntity["patient"] != 2 || byEntity["doctor"] != 1 {
		t.Errorf("per-entity counts = %+v, want patient:2 doctor:1", byEntity)
	}

	if len(got.NeedsAttention.IdPMismatches) != 1 || got.NeedsAttention.IdPMismatches[0].Email != "suspended@client.com" {
		t.Errorf("idp mismatches = %+v, want exactly suspended@client.com", got.NeedsAttention.IdPMismatches)
	}
	if got.NeedsAttention.IdPMismatches[0].Status != identity.AccountSuspended {
		t.Errorf("mismatch status = %q, want suspended", got.NeedsAttention.IdPMismatches[0].Status)
	}
	// Anomalies is a stable, present-but-empty placeholder until the
	// detection subsystem lands — it must be a list, never null.
	if got.NeedsAttention.Anomalies == nil {
		t.Error("anomalies should be an empty list, not null")
	}
}

// Recent activity is the tail of the audit log, most-recent first, so the
// overview shows what just happened without the operator paging the log.
func TestOverviewRecentActivityIsMostRecentFirst(t *testing.T) {
	srv, _, auditStore, _, _, adminTok, _ := overviewServer(t)

	actor := identity.Principal{Type: identity.PrincipalUser, ID: "u@client.com", Email: "u@client.com", Tenant: "client.com"}
	for _, action := range []string{"alpha", "beta"} {
		if err := auditStore.Append(t.Context(), audit.Event{
			Time:     time.Now(),
			Kind:     audit.KindAccess,
			Outcome:  audit.OutcomeAllowed,
			Actor:    actor,
			Action:   action,
			Resource: audit.Resource{Entity: "patient", ID: "p1"},
		}); err != nil {
			t.Fatalf("seeding audit event %q: %v", action, err)
		}
	}

	rec := doReq(t, srv, http.MethodGet, "/api/overview", adminTok, "")
	if rec.status != http.StatusOK {
		t.Fatalf("GET /api/overview: status = %d, want 200", rec.status)
	}
	var got struct {
		RecentActivity []struct {
			Action string `json:"action"`
		} `json:"recent_activity"`
	}
	if err := json.Unmarshal(rec.body.Bytes(), &got); err != nil {
		t.Fatalf("decoding overview: %v", err)
	}

	posAlpha, posBeta := -1, -1
	for i, e := range got.RecentActivity {
		switch e.Action {
		case "alpha":
			posAlpha = i
		case "beta":
			posBeta = i
		}
	}
	if posAlpha < 0 || posBeta < 0 {
		t.Fatalf("recent activity missing seeded events: %+v", got.RecentActivity)
	}
	if posBeta > posAlpha {
		t.Errorf("recent activity is not most-recent-first: beta at %d, alpha at %d", posBeta, posAlpha)
	}
}

// The overview is review work: a plain user may not read it, and an
// unauthenticated caller is rejected before the handler.
func TestOverviewRequiresReviewRole(t *testing.T) {
	srv, _, _, _, _, _, userTok := overviewServer(t)

	if rec := doReq(t, srv, http.MethodGet, "/api/overview", userTok, ""); rec.status != http.StatusForbidden {
		t.Errorf("overview as plain user: status = %d, want 403", rec.status)
	}
	if rec := doReq(t, srv, http.MethodGet, "/api/overview", "", ""); rec.status != http.StatusUnauthorized {
		t.Errorf("overview unauthenticated: status = %d, want 401", rec.status)
	}
}
