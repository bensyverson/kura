package smoke

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// healthyServer mimics the open surface of a real `kura serve`: health
// and readiness answer 200, and any /api/ path rejects an
// unauthenticated request with 401 (the gate is enforced).
func healthyServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// A suite whose probes all pass yields OutcomePass with one passing
// result per check, in order.
func TestSuiteRunAllPass(t *testing.T) {
	ok := func(_ context.Context, _ *http.Client, _ string) error { return nil }
	s := Suite{
		BaseURL: "http://example.test",
		Checks: []Check{
			{Name: "a", Probe: ok},
			{Name: "b", Probe: ok},
		},
	}
	rep := s.Run(context.Background(), http.DefaultClient)
	if rep.Outcome != OutcomePass {
		t.Fatalf("Outcome = %v, want OutcomePass", rep.Outcome)
	}
	if len(rep.Results) != 2 {
		t.Fatalf("len(Results) = %d, want 2", len(rep.Results))
	}
	for _, r := range rep.Results {
		if !r.Passed {
			t.Errorf("check %q should have passed", r.Name)
		}
	}
	if !rep.Passed() {
		t.Errorf("Report.Passed() = false, want true")
	}
}

// A reachable server with one failing check yields OutcomeFail. The
// failing result carries a detail; every check still runs.
func TestSuiteRunReportsFailure(t *testing.T) {
	ok := func(_ context.Context, _ *http.Client, _ string) error { return nil }
	bad := func(_ context.Context, _ *http.Client, _ string) error {
		return errors.New("returned 500, want 200")
	}
	s := Suite{
		BaseURL: "http://example.test",
		Checks: []Check{
			{Name: "a", Probe: ok},
			{Name: "b", Probe: bad},
			{Name: "c", Probe: ok},
		},
	}
	rep := s.Run(context.Background(), http.DefaultClient)
	if rep.Outcome != OutcomeFail {
		t.Fatalf("Outcome = %v, want OutcomeFail", rep.Outcome)
	}
	if len(rep.Results) != 3 {
		t.Fatalf("len(Results) = %d, want 3 (every check runs on a reachable server)", len(rep.Results))
	}
	if rep.Results[1].Passed {
		t.Errorf("check b should have failed")
	}
	if rep.Results[1].Detail == "" {
		t.Errorf("failing check should carry a detail message")
	}
	if rep.Passed() {
		t.Errorf("Report.Passed() = true, want false")
	}
}

// A probe that returns an Unreachable error short-circuits the suite:
// the remaining checks do not run, and the outcome is Unreachable.
func TestSuiteRunUnreachableStopsEarly(t *testing.T) {
	var ranSecond bool
	unreachable := func(_ context.Context, _ *http.Client, _ string) error {
		return Unreachable(errors.New("connection refused"))
	}
	second := func(_ context.Context, _ *http.Client, _ string) error {
		ranSecond = true
		return nil
	}
	s := Suite{
		BaseURL: "http://example.test",
		Checks: []Check{
			{Name: "reachable", Probe: unreachable},
			{Name: "second", Probe: second},
		},
	}
	rep := s.Run(context.Background(), http.DefaultClient)
	if rep.Outcome != OutcomeUnreachable {
		t.Fatalf("Outcome = %v, want OutcomeUnreachable", rep.Outcome)
	}
	if ranSecond {
		t.Errorf("checks after an unreachable result should not run")
	}
	if len(rep.Results) != 1 {
		t.Fatalf("len(Results) = %d, want 1 (short-circuit on unreachable)", len(rep.Results))
	}
}

// The default suite passes cleanly against a server that presents the
// real open surface.
func TestDefaultSuiteAgainstHealthyServer(t *testing.T) {
	srv := healthyServer(t)
	rep := DefaultSuite(srv.URL).Run(context.Background(), srv.Client())
	if rep.Outcome != OutcomePass {
		t.Fatalf("Outcome = %v, want OutcomePass\nresults: %+v", rep.Outcome, rep.Results)
	}
	// Sanity: the default suite covers reachability, readiness, and
	// auth enforcement.
	if len(rep.Results) < 3 {
		t.Errorf("default suite ran %d checks, want at least 3", len(rep.Results))
	}
}

// If /api/ answers 200 to an unauthenticated request, the gate is not
// enforced — the auth-enforcement check must fail.
func TestDefaultSuiteDetectsMissingAuth(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	rep := DefaultSuite(srv.URL).Run(context.Background(), srv.Client())
	if rep.Outcome != OutcomeFail {
		t.Fatalf("Outcome = %v, want OutcomeFail (auth not enforced)\nresults: %+v", rep.Outcome, rep.Results)
	}
}

// The outcome serializes as its string name, so an agent reads
// "pass"/"fail"/"unreachable" rather than an integer.
func TestOutcomeMarshalsAsString(t *testing.T) {
	for outcome, want := range map[Outcome]string{
		OutcomePass:        `"pass"`,
		OutcomeFail:        `"fail"`,
		OutcomeUnreachable: `"unreachable"`,
	} {
		got, err := json.Marshal(outcome)
		if err != nil {
			t.Fatalf("Marshal(%v): %v", outcome, err)
		}
		if string(got) != want {
			t.Errorf("Marshal(%v) = %s, want %s", outcome, got, want)
		}
	}
}

// Pointed at a URL with nothing listening, the default suite reports
// Unreachable rather than Fail.
func TestDefaultSuiteUnreachable(t *testing.T) {
	// A server we immediately close, so the port is dead.
	srv := httptest.NewServer(http.NewServeMux())
	url := srv.URL
	srv.Close()

	rep := DefaultSuite(url).Run(context.Background(), http.DefaultClient)
	if rep.Outcome != OutcomeUnreachable {
		t.Fatalf("Outcome = %v, want OutcomeUnreachable\nresults: %+v", rep.Outcome, rep.Results)
	}
}
