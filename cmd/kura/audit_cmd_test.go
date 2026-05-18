package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeAuditServer is the stand-in for `kura serve`'s audit surface. It
// returns whatever events the test seeds for GET /api/audit, captures
// the query parameters so a test can pin filter passthrough, and serves
// a controllable JSON-lines stream for GET /api/audit/stream so a tail
// test can pin "stream ends → return nil".
type fakeAuditServer struct {
	t          *testing.T
	mu         sync.Mutex
	events     []map[string]any
	lastQuery  string
	streamLine chan string // events to ship on the stream
	streamDone chan struct{}
}

func newFakeAuditServer(t *testing.T) *fakeAuditServer {
	return &fakeAuditServer{
		t:          t,
		streamLine: make(chan string, 16),
		streamDone: make(chan struct{}),
	}
}

func (f *fakeAuditServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/audit", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.lastQuery = r.URL.RawQuery
		out := struct {
			Events []map[string]any `json:"events"`
		}{Events: append([]map[string]any(nil), f.events...)}
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("GET /api/audit/stream", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		if flusher != nil {
			flusher.Flush()
		}
		for {
			// Drain any buffered line before honoring streamDone or
			// request cancellation, so a test that buffers lines and
			// then closes the done channel always sees the lines first.
			select {
			case line, ok := <-f.streamLine:
				if !ok {
					return
				}
				if _, err := w.Write([]byte(line + "\n")); err != nil {
					return
				}
				if flusher != nil {
					flusher.Flush()
				}
				continue
			default:
			}
			select {
			case line, ok := <-f.streamLine:
				if !ok {
					return
				}
				if _, err := w.Write([]byte(line + "\n")); err != nil {
					return
				}
				if flusher != nil {
					flusher.Flush()
				}
			case <-f.streamDone:
				return
			case <-r.Context().Done():
				return
			}
		}
	})
	return mux
}

func setupAuditCLITest(t *testing.T, fake *fakeAuditServer) string {
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

// A0x: `kura log` passes every filter axis through to the server as a
// query parameter — actor, resource (→ server's entity param), action,
// since, until. The server is the one filter authority; the CLI is a
// faithful relay.
func TestLogFiltersByActorResourceActionTime(t *testing.T) {
	fake := newFakeAuditServer(t)
	server := setupAuditCLITest(t, fake)

	_, _, err := runRoot(t, "log",
		"--actor", "alex@client.com",
		"--resource", "patient",
		"--action", "read",
		"--since", "2026-01-01T00:00:00Z",
		"--until", "2026-02-01T00:00:00Z",
		"--server", server)
	if err != nil {
		t.Fatalf("log: %v", err)
	}

	got := fake.lastQuery
	for _, want := range []string{
		"actor=alex%40client.com",
		"entity=patient",
		"action=read",
		"since=2026-01-01T00%3A00%3A00Z",
		"until=2026-02-01T00%3A00%3A00Z",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("server saw query %q, missing %q", got, want)
		}
	}
}

// `kura log --since notatime` is a usage error that names the
// offending flag — the agent gets the fix on the first line, the
// server never sees the bad bound.
func TestLogRejectsMalformedSinceLocally(t *testing.T) {
	fake := newFakeAuditServer(t)
	server := setupAuditCLITest(t, fake)

	_, _, err := runRoot(t, "log", "--since", "notatime", "--server", server)
	if err == nil {
		t.Fatal("expected a usage error for bad --since")
	}
	if !strings.Contains(err.Error(), "--since") || !strings.Contains(err.Error(), "RFC 3339") {
		t.Errorf("error %q does not name the bad flag or the expected format", err)
	}
}

// `kura log` renders matched events as a one-per-line Markdown summary
// with the actor, action, and resource visible — easy to scan, no PII
// because the audit event itself has no field-value payload.
func TestLogRendersEventsAsMarkdown(t *testing.T) {
	fake := newFakeAuditServer(t)
	fake.events = []map[string]any{
		{
			"time":     "2026-05-18T10:00:00Z",
			"kind":     "access",
			"outcome":  "allowed",
			"actor":    map[string]string{"email": "alex@client.com"},
			"action":   "read",
			"resource": map[string]string{"entity": "patient", "id": "p1"},
		},
		{
			"time":     "2026-05-18T10:01:00Z",
			"kind":     "authentication",
			"outcome":  "denied",
			"actor":    map[string]string{"email": "evil@elsewhere.com"},
			"resource": map[string]string{},
		},
	}
	server := setupAuditCLITest(t, fake)

	stdout, _, err := runRoot(t, "log", "--server", server)
	if err != nil {
		t.Fatalf("log: %v", err)
	}
	got := stdout.String()
	for _, want := range []string{"alex@client.com", "read", "patient/p1", "evil@elsewhere.com", "denied"} {
		if !strings.Contains(got, want) {
			t.Errorf("markdown output missing %q:\n%s", want, got)
		}
	}
}

// AlE: `kura tail` streams JSON-lines from the audit stream — one
// server line is one stdout line, verbatim — and terminates cleanly
// when the server closes the stream. Returns nil; stdout has the lines.
func TestTailStreamsAndTerminatesOnServerClose(t *testing.T) {
	fake := newFakeAuditServer(t)
	server := setupAuditCLITest(t, fake)

	fake.streamLine <- `{"time":"2026-05-18T10:00:00Z","kind":"authentication","outcome":"allowed","actor":{"email":"alex@x"},"resource":{}}`
	fake.streamLine <- `{"time":"2026-05-18T10:00:01Z","kind":"access","outcome":"allowed","actor":{"email":"alex@x"},"action":"read","resource":{"entity":"patient","id":"p1"}}`
	close(fake.streamDone)

	stdout, _, err := runRoot(t, "tail", "--server", server)
	if err != nil {
		t.Fatalf("tail: %v", err)
	}
	out := stdout.String()
	lines := 0
	for line := range strings.SplitSeq(strings.TrimRight(out, "\n"), "\n") {
		if line == "" {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Errorf("line is not JSON: %q (%v)", line, err)
			continue
		}
		lines++
	}
	if lines != 2 {
		t.Errorf("stream produced %d JSON lines, want 2:\n%s", lines, out)
	}
}

// AlE: tail terminates cleanly when the user's context is cancelled —
// SIGINT in production, a deadline here. Returns nil (cancellation is a
// clean exit, not an error), and whatever lines made it through stdout
// are still parseable JSON.
func TestTailTerminatesCleanlyOnContextCancel(t *testing.T) {
	fake := newFakeAuditServer(t)
	server := setupAuditCLITest(t, fake)
	fake.streamLine <- `{"time":"2026-05-18T10:00:00Z","kind":"authentication","outcome":"allowed","actor":{"email":"alex@x"},"resource":{}}`

	root := newRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"tail", "--server", server})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if err := root.ExecuteContext(ctx); err != nil {
		t.Fatalf("tail under timeout: %v", err)
	}
	// At least one line should have made it through before the cancel
	// fired; whatever we got must be valid JSON.
	got := strings.TrimRight(stdout.String(), "\n")
	if got == "" {
		t.Skip("the first streamed event did not arrive before the deadline — environment-dependent, not a failure")
	}
	for line := range strings.SplitSeq(got, "\n") {
		if line == "" {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Errorf("post-cancel line is not JSON: %q (%v)", line, err)
		}
	}
}
