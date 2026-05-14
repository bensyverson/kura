package server

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// auditServer builds a server whose gate and audit store are wired
// consistently: the same MemStore both backs the gate's recorder and is
// the Config.Audit read seam, so an event the gate writes is an event the
// audit endpoints can read. It returns the server, the shared store (so a
// test can append events directly), and tokens for an admin, an auditor,
// and a plain user.
func auditServer(t *testing.T) (srv *Server, store *audit.MemStore, adminTok, auditorTok, userTok string) {
	t.Helper()
	m := &manifest.Manifest{
		Version: "1",
		Entities: []manifest.Entity{{Name: "patient", Fields: []manifest.Field{
			{Name: "full_name", Type: manifest.FieldString, PII: new(pii.CategoryPerson)},
		}}},
	}
	evaluator, err := cedar.NewEvaluator(cedar.DefaultPolicy(m))
	if err != nil {
		t.Fatalf("building evaluator: %v", err)
	}
	auth := identity.NewAuthenticator([]byte("test-signing-secret"))
	users := data.NewMemUserStore()
	for email, role := range map[string]string{
		"admin@client.com":   "admin",
		"auditor@client.com": "auditor",
		"user@client.com":    "user",
	} {
		if err := users.AddUser(t.Context(), email); err != nil {
			t.Fatalf("seeding user %s: %v", email, err)
		}
		if err := users.AssignRoles(t.Context(), email, role); err != nil {
			t.Fatalf("seeding role for %s: %v", email, err)
		}
	}

	store = audit.NewMemStore()
	recorder := audit.NewRecorder(store)
	g, err := gate.New(auth, evaluator, users, m, pii.NewScanner(pii.NewFakeDetector()), recorder)
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}

	cfg, _ := testConfig(t, "127.0.0.1:0")
	cfg.Auth = auth
	cfg.Gate = g
	cfg.Users = users
	cfg.Recorder = recorder
	cfg.Audit = store
	srv, err = New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	mint := func(email string) string {
		tok, err := auth.Issue(identity.Principal{Type: identity.PrincipalUser, ID: email, Email: email, Domain: "client.com"}, time.Hour)
		if err != nil {
			t.Fatalf("issuing token for %s: %v", email, err)
		}
		return tok
	}
	return srv, store,
		mint("admin@client.com"),
		mint("auditor@client.com"),
		mint("user@client.com")
}

// seedAuditEvents appends a fixed set of patient-entity events at known
// times, actors, and actions, so a filter test has a deterministic
// corpus that the audit endpoints' own self-events cannot pollute (those
// land on the audit_log entity, not patient).
func seedAuditEvents(t *testing.T, store *audit.MemStore) (t1, t2, t3 time.Time) {
	t.Helper()
	t1 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 = time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	t3 = time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)
	events := []audit.Event{
		{Time: t1, Kind: audit.KindAccess, Outcome: audit.OutcomeAllowed,
			Actor:  identity.Principal{Type: identity.PrincipalUser, ID: "alice@client.com"},
			Action: "read", Resource: audit.Resource{Entity: "patient", ID: "1"}},
		{Time: t2, Kind: audit.KindAccess, Outcome: audit.OutcomeAllowed,
			Actor:  identity.Principal{Type: identity.PrincipalUser, ID: "bob@client.com"},
			Action: "write", Resource: audit.Resource{Entity: "patient", ID: "2"}},
		{Time: t3, Kind: audit.KindAccess, Outcome: audit.OutcomeAllowed,
			Actor:  identity.Principal{Type: identity.PrincipalUser, ID: "alice@client.com"},
			Action: "read", Resource: audit.Resource{Entity: "patient", ID: "3"}},
	}
	for _, e := range events {
		if err := store.Append(t.Context(), e); err != nil {
			t.Fatalf("seeding audit event: %v", err)
		}
	}
	return t1, t2, t3
}

type auditQueryBody struct {
	Events []struct {
		Time    time.Time `json:"time"`
		Kind    string    `json:"kind"`
		Outcome string    `json:"outcome"`
		Action  string    `json:"action"`
		Actor   struct {
			ID string `json:"id"`
		} `json:"actor"`
		Resource struct {
			Entity string `json:"entity"`
			ID     string `json:"id"`
		} `json:"resource"`
	} `json:"events"`
}

// LXa: audit queries support actor/resource/action/time filters.
func TestAuditQueryFiltersByActorEntityActionTime(t *testing.T) {
	srv, store, _, auditorTok, _ := auditServer(t)
	t1, t2, t3 := seedAuditEvents(t, store)
	_ = t1

	query := func(qs string) auditQueryBody {
		rec := doReq(t, srv, http.MethodGet, "/api/audit?entity=patient&"+qs, auditorTok, "")
		if rec.status != http.StatusOK {
			t.Fatalf("GET /api/audit?%s: status = %d, want 200; body %s", qs, rec.status, rec.body.String())
		}
		var body auditQueryBody
		if err := json.Unmarshal(rec.body.Bytes(), &body); err != nil {
			t.Fatalf("decoding audit body %q: %v", rec.body.String(), err)
		}
		return body
	}

	if got := query("actor=alice@client.com"); len(got.Events) != 2 {
		t.Errorf("filter by actor: got %d events, want 2", len(got.Events))
	}
	if got := query("action=write"); len(got.Events) != 1 || got.Events[0].Action != "write" {
		t.Errorf("filter by action: got %+v, want the one write event", got.Events)
	}
	if got := query("since=" + t2.Format(time.RFC3339)); len(got.Events) != 2 {
		t.Errorf("filter by since (inclusive): got %d events, want 2 (t2, t3)", len(got.Events))
	}
	if got := query("until=" + t3.Format(time.RFC3339)); len(got.Events) != 2 {
		t.Errorf("filter by until (exclusive): got %d events, want 2 (t1, t2)", len(got.Events))
	}
	if got := query("actor=alice@client.com&action=read&since=" + t2.Format(time.RFC3339)); len(got.Events) != 1 {
		t.Errorf("combined filters: got %d events, want 1", len(got.Events))
	}
}

// A malformed time filter is a client error, not a server error.
func TestAuditQueryRejectsBadTimeFilter(t *testing.T) {
	srv, _, _, auditorTok, _ := auditServer(t)
	rec := doReq(t, srv, http.MethodGet, "/api/audit?since=not-a-time", auditorTok, "")
	if rec.status != http.StatusBadRequest {
		t.Errorf("bad since filter: status = %d, want 400", rec.status)
	}
}

// LXa: reading the audit log is review work — the auditor and the admin
// may do it, a plain user may not, and an unauthenticated caller may not.
func TestAuditQueryRequiresReviewRole(t *testing.T) {
	srv, _, adminTok, auditorTok, userTok := auditServer(t)

	if rec := doReq(t, srv, http.MethodGet, "/api/audit", "", ""); rec.status != http.StatusUnauthorized {
		t.Errorf("query audit unauthenticated: status = %d, want 401", rec.status)
	}
	if rec := doReq(t, srv, http.MethodGet, "/api/audit", userTok, ""); rec.status != http.StatusForbidden {
		t.Errorf("query audit as plain user: status = %d, want 403", rec.status)
	}
	if rec := doReq(t, srv, http.MethodGet, "/api/audit", auditorTok, ""); rec.status != http.StatusOK {
		t.Errorf("query audit as auditor: status = %d, want 200", rec.status)
	}
	if rec := doReq(t, srv, http.MethodGet, "/api/audit", adminTok, ""); rec.status != http.StatusOK {
		t.Errorf("query audit as admin: status = %d, want 200", rec.status)
	}
}

// LXa: access to the audit log is itself authorized and audited — a query
// leaves an authorization and an access event on the audit_log resource.
func TestAuditAccessIsItselfAudited(t *testing.T) {
	srv, store, _, auditorTok, _ := auditServer(t)

	if rec := doReq(t, srv, http.MethodGet, "/api/audit", auditorTok, ""); rec.status != http.StatusOK {
		t.Fatalf("query audit: status = %d, want 200", rec.status)
	}

	events, err := store.Query(t.Context(), audit.Filter{Entity: "audit_log"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	var authz, access bool
	for _, e := range events {
		if e.Actor.ID != "auditor@client.com" {
			continue
		}
		switch e.Kind {
		case audit.KindAuthorization:
			authz = true
		case audit.KindAccess:
			access = true
		}
	}
	if !authz || !access {
		t.Errorf("querying the audit log left authz=%v access=%v on audit_log, want both true", authz, access)
	}
}

// kat: the stream endpoint emits JSON-lines — one audit Event per line,
// for events appended after the subscription opens.
func TestAuditStreamEmitsJSONLines(t *testing.T) {
	srv, store, _, auditorTok, _ := auditServer(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	ctx := t.Context()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/audit/stream", nil)
	req.Header.Set("Authorization", "Bearer "+auditorTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("opening stream: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stream status = %d, want 200", resp.StatusCode)
	}

	// The subscription is live once the response headers are flushed, so
	// an event appended now must reach the stream.
	want := audit.Event{
		Time: time.Now(), Kind: audit.KindAccess, Outcome: audit.OutcomeAllowed,
		Actor:    identity.Principal{Type: identity.PrincipalUser, ID: "carol@client.com"},
		Action:   "read",
		Resource: audit.Resource{Entity: "patient", ID: "7"},
	}
	if err := store.Append(context.Background(), want); err != nil {
		t.Fatalf("Append: %v", err)
	}

	lines := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		if sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()

	select {
	case line, ok := <-lines:
		if !ok {
			t.Fatal("stream closed before emitting a line")
		}
		var got struct {
			Kind   string `json:"kind"`
			Action string `json:"action"`
			Actor  struct {
				ID string `json:"id"`
			} `json:"actor"`
			Resource struct {
				Entity string `json:"entity"`
				ID     string `json:"id"`
			} `json:"resource"`
		}
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("stream line %q is not JSON: %v", line, err)
		}
		if got.Actor.ID != "carol@client.com" || got.Action != "read" || got.Resource.ID != "7" {
			t.Errorf("streamed event = %+v, want the appended carol/read/7 event", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no line emitted on the stream within 2s")
	}
}

// kat: the stream endpoint is itself access-controlled — a plain user and
// an unauthenticated caller are refused before any event is streamed.
func TestAuditStreamIsAccessControlled(t *testing.T) {
	srv, _, _, _, userTok := auditServer(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	for _, tc := range []struct {
		name, token string
		want        int
	}{
		{"unauthenticated", "", http.StatusUnauthorized},
		{"plain user", userTok, http.StatusForbidden},
	} {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/audit/stream", nil)
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("stream as %s: status = %d, want %d", tc.name, resp.StatusCode, tc.want)
		}
	}
}

// Both audit routes are gated routes — they go through the core gate, so
// they are authorized and audited by construction, exactly like the data
// and admin routes.
func TestAuditRoutesAreGated(t *testing.T) {
	srv, _, _, _, _ := auditServer(t)
	for _, pattern := range []string{"GET /api/audit", "GET /api/audit/stream"} {
		h, ok := srv.apiRoutes[pattern]
		if !ok {
			t.Errorf("audit route %q is not registered", pattern)
			continue
		}
		if _, gated := h.(gatedRoute); !gated {
			t.Errorf("audit route %q is %T, not a gatedRoute", pattern, h)
		}
	}
}
