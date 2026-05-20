package dashboard

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// auditEvent is a small constructor for one wire audit event the fake
// serves, so the tests read as a list of (time, actor, action, resource)
// rows.
func auditEvent(ts time.Time, actor, action, entity, id, outcome string) auditEventWire {
	var e auditEventWire
	e.Time = ts
	e.Kind = "access"
	e.Outcome = outcome
	e.Actor.Type = "user"
	e.Actor.ID = actor
	e.Actor.Email = actor
	e.Action = action
	e.Resource.Entity = entity
	e.Resource.ID = id
	return e
}

func auditFakeRemote(t *testing.T) *fakeRemote {
	t.Helper()
	fr := newFakeRemote(t)
	fr.auditEvents = []auditEventWire{
		auditEvent(time.Date(2026, 5, 19, 9, 0, 0, 0, time.UTC), "ada@client.example", "read", "patient", "p1", "allowed"),
		auditEvent(time.Date(2026, 5, 19, 10, 30, 5, 0, time.UTC), "boss@client.example", "delete", "patient", "p2", "denied"),
	}
	return fr
}

// The viewer renders the audit events the remote API serves — actor,
// action, resource, outcome, and time all appear server-side.
func TestAuditPageRendersEvents(t *testing.T) {
	fr := auditFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/audit"))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /audit = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"ada@client.example", "read", "patient/p1", "allowed",
		"boss@client.example", "delete", "patient/p2", "denied",
		"2026-05-19 10:30:05",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("audit viewer missing %q; body:\n%s", want, body)
		}
	}
}

// Events render newest-first: the most recent event appears before older
// ones, which is how an auditor reads a log.
func TestAuditPageOrdersNewestFirst(t *testing.T) {
	fr := auditFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/audit"))

	body := rec.Body.String()
	newer := strings.Index(body, "2026-05-19 10:30:05")
	older := strings.Index(body, "2026-05-19 09:00:00")
	if newer < 0 || older < 0 {
		t.Fatalf("expected both timestamps in body:\n%s", body)
	}
	if newer > older {
		t.Errorf("events not newest-first: 10:30 at %d should precede 09:00 at %d", newer, older)
	}
}

// The viewer forwards every filter axis — actor, resource (entity),
// action, and the time window — to the remote API, so filtering is the
// gate's query, not a local sieve.
func TestAuditPageForwardsFilters(t *testing.T) {
	fr := auditFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/audit?actor=ada@client.example&resource=patient&action=read&since=2026-05-19T00:00:00Z&until=2026-05-20T00:00:00Z"))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /audit (filtered) = %d, want 200", rec.Code)
	}
	if fr.auditHits == 0 {
		t.Fatal("audit viewer did not query the remote API")
	}
	q := fr.lastAuditQuery
	if got := q.Get("actor"); got != "ada@client.example" {
		t.Errorf("forwarded actor = %q, want ada@client.example", got)
	}
	if got := q.Get("entity"); got != "patient" {
		t.Errorf("forwarded entity = %q, want patient", got)
	}
	if got := q.Get("action"); got != "read" {
		t.Errorf("forwarded action = %q, want read", got)
	}
	if got := q.Get("since"); got != "2026-05-19T00:00:00Z" {
		t.Errorf("forwarded since = %q, want the RFC3339 lower bound", got)
	}
	if got := q.Get("until"); got != "2026-05-20T00:00:00Z" {
		t.Errorf("forwarded until = %q, want the RFC3339 upper bound", got)
	}
}

// The filter form is rendered with the current values so the operator can
// see and refine what is applied.
func TestAuditPageRendersFilterForm(t *testing.T) {
	fr := auditFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/audit?actor=ada@client.example"))

	body := rec.Body.String()
	for _, want := range []string{
		`name="actor"`, `name="resource"`, `name="action"`, `name="since"`, `name="until"`,
		`value="ada@client.example"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("filter form missing %q; body:\n%s", want, body)
		}
	}
}

// A page that overflows the page size shows the first page and a link to
// the next; the second page shows the remainder and a link back.
func TestAuditPagePaginates(t *testing.T) {
	fr := auditFakeRemote(t)
	// Build more events than a single page holds. Timestamps ascend so the
	// newest-first display has a stable order.
	base := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	total := auditPageSize + 5
	fr.auditEvents = make([]auditEventWire, 0, total)
	for i := range total {
		fr.auditEvents = append(fr.auditEvents, auditEvent(
			base.Add(time.Duration(i)*time.Minute),
			fmt.Sprintf("user%02d@client.example", i), "read", "patient", fmt.Sprintf("p%02d", i), "allowed"))
	}
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	// First page: a "next" link, no "previous".
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/audit"))
	first := rec.Body.String()
	if strings.Count(first, "audit-row") != auditPageSize {
		t.Errorf("first page rendered %d rows, want %d", strings.Count(first, "audit-row"), auditPageSize)
	}
	if !strings.Contains(first, fmt.Sprintf("offset=%d", auditPageSize)) {
		t.Errorf("first page has no next link; body:\n%s", first)
	}

	// Second page: the remaining rows and a "previous" link to offset 0.
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet(fmt.Sprintf("/audit?offset=%d", auditPageSize)))
	second := rec.Body.String()
	if strings.Count(second, "audit-row") != total-auditPageSize {
		t.Errorf("second page rendered %d rows, want %d", strings.Count(second, "audit-row"), total-auditPageSize)
	}
	if !strings.Contains(second, "offset=0") {
		t.Errorf("second page has no previous link; body:\n%s", second)
	}
}

// A malformed time bound is reported in the page as a banner, and the
// dashboard does not forward a bad bound to the remote API.
func TestAuditPageRejectsBadTimeBound(t *testing.T) {
	fr := auditFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/audit?since=not-a-time"))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /audit (bad since) = %d, want 200", rec.Code)
	}
	if fr.auditHits != 0 {
		t.Error("dashboard forwarded a malformed time bound to the remote API")
	}
	if !strings.Contains(rec.Body.String(), "banner-error") {
		t.Errorf("bad time bound did not surface a banner; body:\n%s", rec.Body.String())
	}
}

func TestAuditPageReadsRemoteAndHidesToken(t *testing.T) {
	fr := auditFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "super-secret"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/audit"))

	if fr.auditHits == 0 {
		t.Fatal("audit viewer did not authenticate against the remote API")
	}
	if strings.Contains(rec.Body.String(), "super-secret") {
		t.Error("the bearer token leaked into the audit page HTML")
	}
}
