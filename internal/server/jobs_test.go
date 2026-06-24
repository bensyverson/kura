package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
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

// jobsTestHarness wires an in-process server whose gate's role resolver
// is the same UserStore the admin endpoints manage — like adminServer
// does for the users tests — and replaces the default Jobs manager with
// one the test owns. Tests register kinds before calling startListener.
type jobsTestHarness struct {
	cfg  Config
	auth *identity.Authenticator
	mgr  *jobs.Manager
	mem  *jobs.MemStore
}

func newJobsTestHarness(t *testing.T) *jobsTestHarness {
	t.Helper()
	auth := identity.NewAuthenticator([]byte("test-signing-secret"))
	users := data.NewMemUserStore()
	m := &manifest.Manifest{
		Version:  "1",
		Entities: []manifest.Entity{{Name: "patient", Fields: []manifest.Field{{Name: "id", Type: manifest.FieldString}}}},
	}
	evaluator, err := cedar.NewEvaluator(cedar.DefaultPolicy(m))
	if err != nil {
		t.Fatalf("evaluator: %v", err)
	}
	store := audit.NewMemStore()
	recorder := audit.NewRecorder(store)
	g, err := gate.New(auth, evaluator, users, m, pii.NewScanner(pii.NewFakeDetector()), recorder)
	if err != nil {
		t.Fatalf("gate: %v", err)
	}
	mem := jobs.NewMemStore()
	mgr := jobs.NewManager(mem).WithIdleBackoff(5 * time.Millisecond)
	return &jobsTestHarness{
		cfg: Config{
			Addr:     "127.0.0.1:0",
			Logger:   discardLogger(),
			Auth:     auth,
			Recorder: recorder,
			Google:   &fakeGoogle{consentURL: "https://accounts.google.example/auth"},
			Trust:    testTrust(),
			TokenTTL: time.Hour,
			Gate:     g,
			Records:  data.NewMemStore(),
			Writer:   data.NewMemStore(),
			Edges:    data.NewMemStore(),
			Users:    users,
			IdP:      identity.NewFakeDirectory(),
			Audit:    store,
			Jobs:     mgr,
			Reviews:  review.NewMemStore(),
		},
		auth: auth,
		mgr:  mgr,
		mem:  mem,
	}
}

// seedActor adds an authorized actor and assigns it the given roles, so
// the gate's role resolver (which is the same UserStore the admin
// endpoints manage) sees the role too. It returns a bearer token for
// the actor.
func (h *jobsTestHarness) seedActor(t *testing.T, email string, principalType identity.PrincipalType, roles ...string) string {
	t.Helper()
	if err := h.cfg.Users.AddUser(context.Background(), email); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if len(roles) > 0 {
		if err := h.cfg.Users.AssignRoles(context.Background(), email, roles...); err != nil {
			t.Fatalf("AssignRoles: %v", err)
		}
	}
	tok, err := h.auth.Issue(identity.Principal{
		Type: principalType, ID: email, Email: email, Tenant: "client.com",
	}, time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return tok
}

// startListener boots the server on a real TCP listener and returns the
// base URL plus a stop function. Tests that need the worker running
// (orphan recovery) use this form; tests that only need request/response
// use serveHTTP.
func (h *jobsTestHarness) startListener(t *testing.T) (string, func()) {
	t.Helper()
	srv, err := New(h.cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	select {
	case <-srv.Ready():
	case err := <-done:
		t.Fatalf("server exited before becoming ready: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("server never became ready")
	}
	return "http://" + srv.BoundAddr(), func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("server did not shut down")
		}
	}
}

// New refuses a Config with no Jobs manager — async ops are part of the
// API surface, so the server cannot come into existence without the
// ledger that backs them.
func TestNewRequiresJobsManager(t *testing.T) {
	cfg, _ := testConfig(t, "127.0.0.1:0")
	cfg.Jobs = nil
	if _, err := New(cfg); err == nil {
		t.Error("New returned no error when Jobs was nil")
	}
}

// POST /api/jobs submits a job; GET /api/jobs/{id} reads it back. The
// caller's principal becomes the job's actor — that scoping is how the
// ledger keeps actors separate.
func TestJobsRoundTrip(t *testing.T) {
	h := newJobsTestHarness(t)
	h.mgr.Register("noop", func(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(`"ok"`), nil
	})
	tok := h.seedActor(t, "admin@client.com", identity.PrincipalAdmin, "admin")
	base, stop := h.startListener(t)
	defer stop()

	body, _ := json.Marshal(map[string]any{
		"kind":            "noop",
		"idempotency_key": "k-1",
	})
	resp, err := postJSON(base+"/api/jobs", tok, body)
	if err != nil {
		t.Fatalf("POST /api/jobs: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST status = %d, body = %s", resp.StatusCode, mustString(resp.Body))
	}
	var submitted struct {
		Job     jobs.Job `json:"job"`
		Created bool     `json:"created"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&submitted); err != nil {
		t.Fatalf("decode submit: %v", err)
	}
	resp.Body.Close()
	if !submitted.Created {
		t.Fatalf("Created = false; want true on a fresh submit")
	}
	if submitted.Job.Actor != "admin@client.com" {
		t.Fatalf("actor = %q; want admin@client.com", submitted.Job.Actor)
	}

	// A retry with the same key returns the same job; created=false.
	resp, err = postJSON(base+"/api/jobs", tok, body)
	if err != nil {
		t.Fatal(err)
	}
	var retried struct {
		Job     jobs.Job `json:"job"`
		Created bool     `json:"created"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&retried); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if retried.Created {
		t.Fatalf("retry Created=true; want false")
	}
	if retried.Job.ID != submitted.Job.ID {
		t.Fatalf("retry id %q != original %q", retried.Job.ID, submitted.Job.ID)
	}

	// GET /api/jobs/{id} returns the same job, eventually with terminal
	// status once the worker drains it.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		getResp, err := getWithToken(base+"/api/jobs/"+submitted.Job.ID, tok)
		if err != nil {
			t.Fatal(err)
		}
		if getResp.StatusCode != http.StatusOK {
			getResp.Body.Close()
			t.Fatalf("GET status = %d", getResp.StatusCode)
		}
		var got jobs.Job
		if err := json.NewDecoder(getResp.Body).Decode(&got); err != nil {
			getResp.Body.Close()
			t.Fatal(err)
		}
		getResp.Body.Close()
		if got.Status.Terminal() {
			if got.Status != jobs.StatusSucceeded {
				t.Fatalf("status = %q; want %q", got.Status, jobs.StatusSucceeded)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("job did not reach terminal within 2s")
}

// GET /api/jobs lists the caller's jobs only — a second actor's jobs
// are invisible. This is the ledger's actor-scoping carried through to
// the wire.
func TestJobsListIsActorScoped(t *testing.T) {
	h := newJobsTestHarness(t)
	h.mgr.Register("noop", func(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
		return nil, nil
	})
	adminTok := h.seedActor(t, "admin@client.com", identity.PrincipalAdmin, "admin")
	secondTok := h.seedActor(t, "second@client.com", identity.PrincipalAdmin, "admin")

	base, stop := h.startListener(t)
	defer stop()

	for _, tok := range []string{adminTok, secondTok} {
		body, _ := json.Marshal(map[string]any{"kind": "noop", "idempotency_key": "k"})
		resp, err := postJSON(base+"/api/jobs", tok, body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("seed POST: status=%d body=%s", resp.StatusCode, mustString(resp.Body))
		}
		resp.Body.Close()
	}

	resp, err := getWithToken(base+"/api/jobs", adminTok)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", resp.StatusCode, mustString(resp.Body))
	}
	var listed struct {
		Jobs []jobs.Job `json:"jobs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(listed.Jobs) != 1 {
		t.Fatalf("admin sees %d jobs; want 1", len(listed.Jobs))
	}
	if listed.Jobs[0].Actor != "admin@client.com" {
		t.Fatalf("listed actor = %q; want admin@client.com", listed.Jobs[0].Actor)
	}
}

// The server stamps the authenticated principal into the job params,
// overwriting whatever the client sent. Identity is asserted by the
// server that authenticated the request — a caller cannot impersonate
// someone else by hand-crafting params.actor. The full principal
// (including Tenant) is carried through, and the client's other params
// fields are preserved.
func TestJobsSubmitStampsAuthenticatedPrincipalOverClientActor(t *testing.T) {
	h := newJobsTestHarness(t)
	gotParams := make(chan json.RawMessage, 1)
	h.mgr.Register("capture", func(_ context.Context, params json.RawMessage) (json.RawMessage, error) {
		gotParams <- params
		return nil, nil
	})
	tok := h.seedActor(t, "admin@client.com", identity.PrincipalAdmin, "admin")
	base, stop := h.startListener(t)
	defer stop()

	// The client tries to impersonate someone in another tenant.
	body, _ := json.Marshal(map[string]any{
		"kind":            "capture",
		"idempotency_key": "k-1",
		"params": map[string]any{
			"actor": map[string]any{
				"type":   "human",
				"id":     "evil@attacker.com",
				"email":  "evil@attacker.com",
				"tenant": "attacker.com",
			},
			"object_key": "backup-x.dump.enc",
		},
	})
	resp, err := postJSON(base+"/api/jobs", tok, body)
	if err != nil {
		t.Fatalf("POST /api/jobs: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST status = %d, body = %s", resp.StatusCode, mustString(resp.Body))
	}
	resp.Body.Close()

	var raw json.RawMessage
	select {
	case raw = <-gotParams:
	case <-time.After(2 * time.Second):
		t.Fatal("handler was never invoked")
	}
	var p struct {
		Actor     identity.Principal `json:"actor"`
		ObjectKey string             `json:"object_key"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("decode stamped params: %v", err)
	}
	if p.Actor.Email != "admin@client.com" {
		t.Errorf("stamped actor email = %q; want admin@client.com (client actor not overwritten)", p.Actor.Email)
	}
	if p.Actor.Tenant != "client.com" {
		t.Errorf("stamped actor tenant = %q; want client.com (full principal not preserved)", p.Actor.Tenant)
	}
	if p.ObjectKey != "backup-x.dump.enc" {
		t.Errorf("object_key = %q; want backup-x.dump.enc (other params clobbered)", p.ObjectKey)
	}
}

// When the client sends params with no actor at all, the server injects
// the authenticated principal — every job kind's handler can rely on
// params.actor naming the real caller.
func TestJobsSubmitInjectsPrincipalWhenParamsHaveNoActor(t *testing.T) {
	h := newJobsTestHarness(t)
	gotParams := make(chan json.RawMessage, 1)
	h.mgr.Register("capture", func(_ context.Context, params json.RawMessage) (json.RawMessage, error) {
		gotParams <- params
		return nil, nil
	})
	tok := h.seedActor(t, "admin@client.com", identity.PrincipalAdmin, "admin")
	base, stop := h.startListener(t)
	defer stop()

	// No params field at all — the CLI's backup verb submits exactly this.
	body, _ := json.Marshal(map[string]any{
		"kind":            "capture",
		"idempotency_key": "k-1",
	})
	resp, err := postJSON(base+"/api/jobs", tok, body)
	if err != nil {
		t.Fatalf("POST /api/jobs: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST status = %d, body = %s", resp.StatusCode, mustString(resp.Body))
	}
	resp.Body.Close()

	var raw json.RawMessage
	select {
	case raw = <-gotParams:
	case <-time.After(2 * time.Second):
		t.Fatal("handler was never invoked")
	}
	var p struct {
		Actor identity.Principal `json:"actor"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("decode stamped params: %v", err)
	}
	if p.Actor.Email != "admin@client.com" {
		t.Errorf("injected actor email = %q; want admin@client.com", p.Actor.Email)
	}
	if p.Actor.Tenant != "client.com" {
		t.Errorf("injected actor tenant = %q; want client.com", p.Actor.Tenant)
	}
}

// Params that are present but not a JSON object cannot carry an actor, so
// the server rejects them with a 400 rather than silently dropping the
// identity stamp.
func TestJobsSubmitRejectsNonObjectParams(t *testing.T) {
	h := newJobsTestHarness(t)
	h.mgr.Register("capture", func(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
		return nil, nil
	})
	tok := h.seedActor(t, "admin@client.com", identity.PrincipalAdmin, "admin")
	base, stop := h.startListener(t)
	defer stop()
	// params is a JSON array, not an object.
	body := []byte(`{"kind":"capture","idempotency_key":"k","params":[1,2,3]}`)
	resp, err := postJSON(base+"/api/jobs", tok, body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", resp.StatusCode)
	}
}

// POST /api/jobs with an unknown kind is 400 — the ledger never accepts
// work no worker can run.
func TestJobsSubmitRejectsUnknownKind(t *testing.T) {
	h := newJobsTestHarness(t)
	tok := h.seedActor(t, "admin@client.com", identity.PrincipalAdmin, "admin")
	base, stop := h.startListener(t)
	defer stop()
	body, _ := json.Marshal(map[string]any{"kind": "no-such", "idempotency_key": "k"})
	resp, err := postJSON(base+"/api/jobs", tok, body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", resp.StatusCode)
	}
}

// A non-admin caller is denied at the gate. The ledger is admin-only;
// the auditor role can read but not submit.
func TestJobsSubmitDeniedForNonAdmin(t *testing.T) {
	h := newJobsTestHarness(t)
	h.mgr.Register("noop", func(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
		return nil, nil
	})
	tok := h.seedActor(t, "user@client.com", identity.PrincipalUser /* no admin role */)
	base, stop := h.startListener(t)
	defer stop()
	body, _ := json.Marshal(map[string]any{"kind": "noop", "idempotency_key": "k"})
	resp, err := postJSON(base+"/api/jobs", tok, body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d; want 403", resp.StatusCode)
	}
}

// The server's startup runs ResetOrphans, so a job left running from a
// previous process boot is back in pending by the time the listener
// opens. The next worker round will pick it up.
func TestServerResetsOrphansOnStartup(t *testing.T) {
	h := newJobsTestHarness(t)
	h.mgr.Register("noop", func(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
		return nil, nil
	})

	// Stage an orphan: submit a pending job, then claim it so it sits in
	// 'running'. This is the simulated mid-job crash — the next worker
	// boot has to recover it.
	submitted, _, err := h.mgr.Submit(context.Background(), "admin@client.com", "noop", "k", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.mem.ClaimNextPending(context.Background()); err != nil {
		t.Fatal(err)
	}

	_, stop := h.startListener(t)
	defer stop()

	// Wait for the worker to drive it back through to terminal.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got, err := h.mgr.Get(context.Background(), "admin@client.com", submitted.ID)
		if err == nil && got.Status.Terminal() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("orphan was not recovered to terminal within 2s")
}

// helpers --------------------------------------------------------------

func postJSON(target, tok string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	return http.DefaultClient.Do(req)
}

func getWithToken(target, tok string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	return http.DefaultClient.Do(req)
}

func mustString(r io.Reader) string {
	b, _ := io.ReadAll(r)
	return strings.TrimSpace(string(b))
}
