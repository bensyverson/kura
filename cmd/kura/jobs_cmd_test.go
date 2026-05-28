package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeJobsServer is the stand-in for `kura serve`'s jobs surface. It
// hands out canned responses for GET /api/jobs and GET /api/jobs/{id},
// and counts the calls so a poll test can assert that --wait kept
// polling rather than answering on the first response.
type fakeJobsServer struct {
	t  *testing.T
	mu sync.Mutex

	// list returned by GET /api/jobs.
	list []map[string]any

	// get serves GET /api/jobs/{id}. The fixture is a script of
	// successive responses; each GET pops the head. If the script runs
	// out, the last entry is returned forever — useful for tests that
	// want a terminal state to hold.
	script []map[string]any
	calls  int32

	// returnError forces a non-200 response for the next get call.
	getErrorStatus int

	// submitted records every POST /api/jobs submission so the backup and
	// restore verb tests can assert on the kind, key, and params sent.
	submitted []jobSubmission
	// submitStatus, when non-zero, makes every POST return that status —
	// the rejected-submission path (e.g. 400 unknown kind).
	submitStatus int
}

// jobSubmission is one captured POST /api/jobs body.
type jobSubmission struct {
	kind   string
	key    string
	params json.RawMessage
}

func newFakeJobsServer(t *testing.T) *fakeJobsServer { return &fakeJobsServer{t: t} }

// submissions returns a copy of the captured POST /api/jobs bodies.
func (f *fakeJobsServer) submissions() []jobSubmission {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]jobSubmission(nil), f.submitted...)
}

func (f *fakeJobsServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/jobs", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Kind           string          `json:"kind"`
			IdempotencyKey string          `json:"idempotency_key"`
			Params         json.RawMessage `json:"params"`
		}
		_ = json.Unmarshal(body, &req)
		f.mu.Lock()
		f.submitted = append(f.submitted, jobSubmission{kind: req.Kind, key: req.IdempotencyKey, params: req.Params})
		fail := f.submitStatus
		f.mu.Unlock()
		if fail != 0 {
			http.Error(w, "rejected", fail)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"job":     map[string]any{"id": "job-1", "kind": req.Kind, "status": "pending"},
			"created": true,
		})
	})
	mux.HandleFunc("GET /api/jobs", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		out := struct {
			Jobs []map[string]any `json:"jobs"`
		}{Jobs: append([]map[string]any(nil), f.list...)}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("GET /api/jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&f.calls, 1)
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.getErrorStatus != 0 {
			http.Error(w, "boom", f.getErrorStatus)
			return
		}
		var resp map[string]any
		switch {
		case len(f.script) == 0:
			http.NotFound(w, r)
			return
		case len(f.script) == 1:
			resp = f.script[0]
		default:
			resp = f.script[0]
			f.script = f.script[1:]
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	return mux
}

// setupJobsCLITest spins up the fake, sets HOME/XDG_CONFIG_HOME to a
// tempdir so the token cache lands there, and seeds the cache with the
// fake's URL.
func setupJobsCLITest(t *testing.T, fake *fakeJobsServer) string {
	t.Helper()
	srv := httptest.NewServer(fake.handler())
	t.Cleanup(srv.Close)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cache, err := defaultTokenCache()
	if err != nil {
		t.Fatalf("defaultTokenCache: %v", err)
	}
	if err := cache.save(srv.URL, "tok"); err != nil {
		t.Fatalf("cache.save: %v", err)
	}
	return srv.URL
}

// `kura jobs list` renders the ledger as a one-line-per-job summary.
// The empty case is reported explicitly so an agent learns "no jobs"
// without grepping.
func TestJobsListRendersJobs(t *testing.T) {
	fake := newFakeJobsServer(t)
	fake.list = []map[string]any{
		{
			"id":              "j-1",
			"kind":            "backup",
			"status":          "succeeded",
			"actor":           "admin@client.com",
			"idempotency_key": "k-1",
			"created_at":      "2026-05-18T10:00:00Z",
			"started_at":      "2026-05-18T10:00:01Z",
			"finished_at":     "2026-05-18T10:00:05Z",
		},
	}
	server := setupJobsCLITest(t, fake)

	stdout, _, err := runRoot(t, "jobs", "list", "--server", server)
	if err != nil {
		t.Fatalf("jobs list: %v", err)
	}
	got := stdout.String()
	for _, want := range []string{"j-1", "backup/succeeded", "2026-05-18T10:00:00Z"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

// The empty-list case is explicit text, not just an empty Markdown
// section — a presenter contract: an agent should never have to grep
// for "no rows".
func TestJobsListExplainsEmpty(t *testing.T) {
	fake := newFakeJobsServer(t)
	server := setupJobsCLITest(t, fake)

	stdout, _, err := runRoot(t, "jobs", "list", "--server", server)
	if err != nil {
		t.Fatalf("jobs list: %v", err)
	}
	if !strings.Contains(stdout.String(), "no jobs on the ledger") {
		t.Errorf("empty list output did not explain itself:\n%s", stdout.String())
	}
}

// `kura jobs get <id>` reads a single job. The pretty output names the
// fields an agent needs to act — status, kind, error/result.
func TestJobsGetRendersOne(t *testing.T) {
	fake := newFakeJobsServer(t)
	fake.script = []map[string]any{
		{
			"id":              "j-1",
			"kind":            "backup",
			"status":          "succeeded",
			"actor":           "admin@client.com",
			"idempotency_key": "k-1",
			"created_at":      "2026-05-18T10:00:00Z",
			"result":          json.RawMessage(`{"ok":true}`),
		},
	}
	server := setupJobsCLITest(t, fake)

	stdout, _, err := runRoot(t, "jobs", "get", "j-1", "--server", server)
	if err != nil {
		t.Fatalf("jobs get: %v", err)
	}
	got := stdout.String()
	for _, want := range []string{"job j-1", "kind:    backup", "status:  succeeded", "result"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

// The criterion: `kura jobs get --wait` polls internally and returns
// when the job reaches a terminal status. The fixture script returns
// pending, then running, then succeeded; the CLI must call at least
// three times and return only after the third response.
func TestJobsGetWaitPollsUntilTerminal(t *testing.T) {
	fake := newFakeJobsServer(t)
	fake.script = []map[string]any{
		{"id": "j-1", "kind": "backup", "status": "pending", "actor": "a@b", "idempotency_key": "k", "created_at": "2026-05-18T10:00:00Z"},
		{"id": "j-1", "kind": "backup", "status": "running", "actor": "a@b", "idempotency_key": "k", "created_at": "2026-05-18T10:00:00Z"},
		{"id": "j-1", "kind": "backup", "status": "succeeded", "actor": "a@b", "idempotency_key": "k", "created_at": "2026-05-18T10:00:00Z"},
	}
	server := setupJobsCLITest(t, fake)

	// Shorten the poll interval so the test stays fast.
	prev := jobsPollInterval
	jobsPollInterval = 5 * time.Millisecond
	defer func() { jobsPollInterval = prev }()

	stdout, _, err := runRoot(t, "jobs", "get", "j-1", "--wait", "--timeout", "2s", "--server", server)
	if err != nil {
		t.Fatalf("jobs get --wait: %v", err)
	}
	if got := atomic.LoadInt32(&fake.calls); got < 3 {
		t.Fatalf("server saw %d GETs; want at least 3 (poll did not iterate)", got)
	}
	if !strings.Contains(stdout.String(), "succeeded") {
		t.Errorf("final output did not show terminal status:\n%s", stdout.String())
	}
}

// `--wait --timeout` surfaces a transient error when the job never
// reaches terminal — the agent gets back a clear message and a retry
// hint, not a silent zero exit.
func TestJobsGetWaitTimesOut(t *testing.T) {
	fake := newFakeJobsServer(t)
	fake.script = []map[string]any{
		{"id": "j-1", "kind": "backup", "status": "running", "actor": "a@b", "idempotency_key": "k", "created_at": "2026-05-18T10:00:00Z"},
	}
	server := setupJobsCLITest(t, fake)

	prev := jobsPollInterval
	jobsPollInterval = 5 * time.Millisecond
	defer func() { jobsPollInterval = prev }()

	_, _, err := runRoot(t, "jobs", "get", "j-1", "--wait", "--timeout", "50ms", "--server", server)
	if err == nil {
		t.Fatal("expected a timeout error from --wait")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("error %q did not mention the timeout", err)
	}
}

// `kura jobs get <missing>` surfaces the server's 404 through the
// shared HTTP-status mapper, the same way every other verb does. The
// taxonomy keeps the agent's error shape consistent.
func TestJobsGetMissingIs404(t *testing.T) {
	fake := newFakeJobsServer(t)
	fake.getErrorStatus = http.StatusNotFound
	server := setupJobsCLITest(t, fake)

	_, _, err := runRoot(t, "jobs", "get", "j-1", "--server", server)
	if err == nil {
		t.Fatal("expected a not-found error")
	}
	if !strings.Contains(err.Error(), "not found") && !strings.Contains(err.Error(), "404") {
		t.Errorf("error %q did not surface the 404", err)
	}
}
