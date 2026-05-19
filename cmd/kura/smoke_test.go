package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bensyverson/kura/internal/clio"
)

// smokeHealthyServer presents the real open surface a passing smoke run
// expects: health and readiness 200, and /api/ rejects an
// unauthenticated request with 401.
func smokeHealthyServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// `kura smoke --server <url>` runs the suite and reports each check with
// a pass marker, exiting 0 when the server is healthy.
func TestSmokeReportsPerCheck(t *testing.T) {
	srv := smokeHealthyServer(t)
	stdout, _, err := runRoot(t, "smoke", "--server", srv.URL)
	if err != nil {
		t.Fatalf("smoke against healthy server: %v", err)
	}
	got := stdout.String()
	for _, want := range []string{"reachable", "ready", "auth-enforced", "PASS"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

// A reachable server that fails a check (here: the gate is not enforced,
// so /api/ answers 200) exits with the internal/escalate code 7.
func TestSmokeExitCodeOnFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	stdout, _, err := runRoot(t, "smoke", "--server", srv.URL)
	if err == nil {
		t.Fatalf("smoke against a broken server should error; stdout=%s", stdout.String())
	}
	if code := clio.ExitCode(err); code != 7 {
		t.Errorf("ExitCode = %d, want 7 (internal/escalate) for a reachable-but-failing server", code)
	}
	// The per-check report is still printed so the caller sees which
	// check failed.
	if !strings.Contains(stdout.String(), "auth-enforced") {
		t.Errorf("failing run should still print the per-check report:\n%s", stdout.String())
	}
}

// An unreachable server exits with the transient/retryable code 6.
func TestSmokeExitCodeUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.NewServeMux())
	url := srv.URL
	srv.Close() // port is now dead

	_, _, err := runRoot(t, "smoke", "--server", url)
	if err == nil {
		t.Fatalf("smoke against an unreachable server should error")
	}
	if code := clio.ExitCode(err); code != 6 {
		t.Errorf("ExitCode = %d, want 6 (transient/retryable) for an unreachable server", code)
	}
}

// `--json` emits a structured report with the outcome and per-check
// results.
func TestSmokeJSON(t *testing.T) {
	srv := smokeHealthyServer(t)
	stdout, _, err := runRoot(t, "smoke", "--server", srv.URL, "--json")
	if err != nil {
		t.Fatalf("smoke --json: %v", err)
	}
	var doc struct {
		Outcome string `json:"outcome"`
		Results []struct {
			Name   string `json:"name"`
			Passed bool   `json:"passed"`
		} `json:"results"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("decoding JSON output: %v\nstdout=%s", err, stdout.String())
	}
	if doc.Outcome != "pass" {
		t.Errorf("outcome = %q, want %q", doc.Outcome, "pass")
	}
	if len(doc.Results) < 3 {
		t.Errorf("expected at least 3 results, got %d", len(doc.Results))
	}
}

// `kura smoke` with no server configured is a usage error (exit 2), not
// a crash.
func TestSmokeNoServerIsUsageError(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	_, _, err := runRoot(t, "smoke")
	if err == nil {
		t.Fatalf("smoke with no server should error")
	}
	if code := clio.ExitCode(err); code != 2 {
		t.Errorf("ExitCode = %d, want 2 (usage) when no server is configured", code)
	}
}
