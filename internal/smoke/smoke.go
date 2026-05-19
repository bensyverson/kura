// Package smoke runs an end-to-end health suite against a running
// `kura serve` addressed by URL. The same suite is meant to run in three
// places — a CI ephemeral deploy, a staging environment, and a freshly
// provisioned client system — so it depends only on the public HTTP
// surface and never on in-process state.
//
// A run produces a Report: one Result per check plus a single Outcome
// that the caller maps to an exit code. The three outcomes are distinct
// on purpose — a clean pass, a reachable-but-failing server, and an
// unreachable server each demand a different next action (done, escalate,
// retry).
package smoke

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Outcome is the suite-level classification of a run. It is deliberately
// three-valued: "reachable but failing" and "unreachable" are different
// problems with different remedies.
type Outcome int

const (
	// OutcomePass means every check passed.
	OutcomePass Outcome = iota

	// OutcomeFail means the server was reachable but at least one check
	// failed — the deployment is broken, not absent. Escalate.
	OutcomeFail

	// OutcomeUnreachable means the server could not be contacted at all
	// (connection refused, DNS failure, timeout). It may simply not be
	// up yet, so this is the retryable outcome.
	OutcomeUnreachable
)

// String renders the outcome for logs and the Markdown report.
func (o Outcome) String() string {
	switch o {
	case OutcomePass:
		return "pass"
	case OutcomeFail:
		return "fail"
	case OutcomeUnreachable:
		return "unreachable"
	default:
		return "unknown"
	}
}

// MarshalJSON emits the outcome as its string name so an agent parsing
// the JSON report reads "pass"/"fail"/"unreachable", not an integer it
// would have to map back.
func (o Outcome) MarshalJSON() ([]byte, error) {
	return json.Marshal(o.String())
}

// Result is the outcome of a single check.
type Result struct {
	Name   string `json:"name"`
	Desc   string `json:"desc,omitempty"`
	Passed bool   `json:"passed"`
	// Detail explains a failure. It is empty on a pass.
	Detail string `json:"detail,omitempty"`
}

// Check is one probe in a suite: a stable name, a one-line description,
// and a probe that returns nil on success or an error describing the
// failure. A probe that wants to signal "the server is unreachable"
// (rather than "the server answered wrongly") wraps its error with
// Unreachable.
type Check struct {
	Name  string
	Desc  string
	Probe func(ctx context.Context, client *http.Client, baseURL string) error
}

// Report is the full result of a suite run.
type Report struct {
	BaseURL string   `json:"base_url"`
	Outcome Outcome  `json:"outcome"`
	Results []Result `json:"results"`
}

// Passed reports whether the run was a clean pass.
func (r Report) Passed() bool { return r.Outcome == OutcomePass }

// Suite is an ordered set of checks against one server.
type Suite struct {
	BaseURL string
	Checks  []Check
}

// Run executes every check in order and returns a Report. If any probe
// reports the server is unreachable (see Unreachable), the run
// short-circuits: remaining checks would only produce noise, so the
// report holds the results gathered so far and the Unreachable outcome.
// Otherwise the outcome is Fail if any check failed, else Pass.
func (s Suite) Run(ctx context.Context, client *http.Client) Report {
	rep := Report{BaseURL: s.BaseURL, Outcome: OutcomePass}
	for _, c := range s.Checks {
		err := c.Probe(ctx, client, s.BaseURL)
		res := Result{Name: c.Name, Desc: c.Desc, Passed: err == nil}
		if err != nil {
			res.Detail = err.Error()
		}
		rep.Results = append(rep.Results, res)
		if isUnreachable(err) {
			rep.Outcome = OutcomeUnreachable
			return rep
		}
		if err != nil {
			rep.Outcome = OutcomeFail
		}
	}
	return rep
}

// unreachableError marks a transport-level failure: the server could not
// be contacted at all, as opposed to answering incorrectly. The runner
// promotes it to OutcomeUnreachable and stops.
type unreachableError struct{ err error }

func (e *unreachableError) Error() string { return e.err.Error() }
func (e *unreachableError) Unwrap() error { return e.err }

// Unreachable wraps a transport-level error so the suite runner classifies
// the whole run as OutcomeUnreachable rather than OutcomeFail.
func Unreachable(err error) error { return &unreachableError{err: err} }

// isUnreachable reports whether err (or anything it wraps) is an
// unreachableError.
func isUnreachable(err error) bool {
	var u *unreachableError
	return errors.As(err, &u)
}

// DefaultSuite returns the checks runnable against the current server
// surface: the server is reachable, it reports ready, and the gate
// rejects an unauthenticated /api/ request. Deeper flow checks (audit,
// PII, LLM gateway) are added as the server grows the smoke hooks they
// need.
func DefaultSuite(baseURL string) Suite {
	base := strings.TrimRight(baseURL, "/")
	return Suite{
		BaseURL: base,
		Checks: []Check{
			{
				Name: "reachable",
				Desc: "GET /healthz answers 200",
				Probe: func(ctx context.Context, client *http.Client, base string) error {
					resp, err := get(ctx, client, base+"/healthz")
					if err != nil {
						return Unreachable(fmt.Errorf("GET /healthz: %w", err))
					}
					defer resp.Body.Close()
					if resp.StatusCode != http.StatusOK {
						return fmt.Errorf("GET /healthz returned %d, want 200", resp.StatusCode)
					}
					return nil
				},
			},
			{
				Name: "ready",
				Desc: "GET /readyz answers 200",
				Probe: func(ctx context.Context, client *http.Client, base string) error {
					resp, err := get(ctx, client, base+"/readyz")
					if err != nil {
						return Unreachable(fmt.Errorf("GET /readyz: %w", err))
					}
					defer resp.Body.Close()
					if resp.StatusCode != http.StatusOK {
						return fmt.Errorf("GET /readyz returned %d, want 200", resp.StatusCode)
					}
					return nil
				},
			},
			{
				Name: "auth-enforced",
				Desc: "an unauthenticated /api/ request is rejected with 401",
				Probe: func(ctx context.Context, client *http.Client, base string) error {
					resp, err := get(ctx, client, base+"/api/_smoke_auth_check")
					if err != nil {
						return Unreachable(fmt.Errorf("GET /api/_smoke_auth_check: %w", err))
					}
					defer resp.Body.Close()
					if resp.StatusCode != http.StatusUnauthorized {
						return fmt.Errorf("unauthenticated /api/ request returned %d, want 401 — the gate is not enforced", resp.StatusCode)
					}
					return nil
				},
			},
		},
	}
}

// get issues a context-bound GET. It is the single HTTP entry point for
// the built-in probes so transport errors surface uniformly.
func get(ctx context.Context, client *http.Client, url string) (*http.Response, error) {
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}
