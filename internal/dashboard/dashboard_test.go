package dashboard

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bensyverson/kura/internal/cedar"
	"github.com/bensyverson/kura/internal/identity"
	"github.com/bensyverson/kura/internal/manifest"
	"github.com/bensyverson/kura/internal/review"
)

// staticToken is a TokenSource that returns a fixed token, or an error
// standing in for "no cached credential".
type staticToken struct {
	token string
	err   error
}

func (s staticToken) Token() (string, error) { return s.token, s.err }

// fakeRemote stands in for a remote kura serve. It records what the
// dashboard's server-side API client sent, so a test can prove data
// access goes through the remote API (criterion IK2) and carries the
// cached bearer token.
type fakeRemote struct {
	*httptest.Server
	mu        sync.Mutex
	lastAuth  string
	lastPath  string
	hits      int
	status    int // override response status; 0 means 200 + body
	principal identity.Principal

	// overview is what /api/overview serves; overviewHits and overviewAuth
	// record that the dashboard fetched it server-side with the token. They
	// are tracked separately from the whoami counters so the skeleton's
	// whoami assertions stay meaningful now that the index makes two reads.
	overview     overviewData
	overviewHits int
	overviewAuth string

	// users, policy, and mismatches back the Users & roles page reads;
	// mutations records every state-changing call the dashboard made to a
	// user/role endpoint, so a test can prove a UI action reached the
	// remote API carrying the bearer token.
	users      []userRow
	policy     cedar.Policy
	mismatches []mismatchRow
	mutations  []recordedMutation

	// auditEvents back the Audit log viewer read; auditHits and
	// lastAuditQuery record that the dashboard fetched the log server-side
	// and which filter axes it forwarded, so a test can prove the viewer's
	// filters reach the remote API.
	auditEvents    []auditEventWire
	auditHits      int
	lastAuditQuery url.Values

	// schema backs GET /api/manifest and records back the data routes
	// (GET /api/{entity} and GET /api/{entity}/{id}). lastListQuery records
	// the pagination the dashboard forwarded; the records are served as the
	// remote already masked them, so a test can prove the browser renders
	// masked output verbatim and never unmasks.
	schema        manifest.Manifest
	records       map[string][]recordWire
	lastListQuery url.Values
	manifestHits  int

	// reviews is a real in-memory review store the fake's /api/reviews
	// handlers delegate to, so the access-review page tests run against
	// realistic store behavior.
	reviews *review.MemStore
}

// recordWire is one record as the remote serves it — an id and a map of
// (already-masked) field values.
type recordWire struct {
	ID     string            `json:"id"`
	Fields map[string]string `json:"fields"`
}

// auditEventWire mirrors the remote API's audit-event JSON shape; the fake
// uses it to serve GET /api/audit the same envelope the dashboard decodes.
type auditEventWire struct {
	Time    time.Time `json:"time"`
	Kind    string    `json:"kind"`
	Outcome string    `json:"outcome"`
	Actor   struct {
		Type   string `json:"type,omitempty"`
		ID     string `json:"id,omitempty"`
		Email  string `json:"email,omitempty"`
		Tenant string `json:"tenant,omitempty"`
	} `json:"actor"`
	Action   string `json:"action,omitempty"`
	Resource struct {
		Entity string `json:"entity,omitempty"`
		ID     string `json:"id,omitempty"`
	} `json:"resource"`
	IP string `json:"ip,omitempty"`
}

// recordedMutation is one state-changing call the dashboard's API client
// made against the remote — what a UI action turned into on the wire.
type recordedMutation struct {
	Method string
	Path   string
	Auth   string
	Body   string
}

func newFakeRemote(t *testing.T) *fakeRemote {
	t.Helper()
	fr := &fakeRemote{
		principal: identity.Principal{
			Type:   identity.PrincipalAdmin,
			ID:     "boss@client.example",
			Email:  "boss@client.example",
			Tenant: "client.example",
		},
		overview: overviewData{
			Status: "operational",
			Tier:   "unknown (Phase 6+)",
			Counts: overviewCounts{
				Entities: 2,
				Records:  5,
				Users:    3,
				ByEntity: []overviewEntityCount{{Entity: "patient", Count: 4}, {Entity: "doctor", Count: 1}},
			},
			NeedsAttention: overviewAttention{IdPMismatches: nil, Anomalies: []string{}},
		},
		reviews: review.NewMemStore(),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/whoami", func(w http.ResponseWriter, r *http.Request) {
		fr.mu.Lock()
		fr.hits++
		fr.lastAuth = r.Header.Get("Authorization")
		fr.lastPath = r.URL.Path
		status := fr.status
		fr.mu.Unlock()
		if status != 0 && status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(fr.principal)
	})
	mux.HandleFunc("GET /api/overview", func(w http.ResponseWriter, r *http.Request) {
		fr.mu.Lock()
		fr.overviewHits++
		fr.overviewAuth = r.Header.Get("Authorization")
		status := fr.status
		ov := fr.overview
		fr.mu.Unlock()
		if status != 0 && status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ov)
	})
	mux.HandleFunc("GET /api/users", func(w http.ResponseWriter, r *http.Request) {
		fr.mu.Lock()
		status := fr.status
		out := usersResponse{Users: append([]userRow(nil), fr.users...)}
		fr.mu.Unlock()
		if status != 0 && status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("GET /api/policy", func(w http.ResponseWriter, r *http.Request) {
		fr.mu.Lock()
		status := fr.status
		p := fr.policy
		fr.mu.Unlock()
		if status != 0 && status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(p)
	})
	mux.HandleFunc("GET /api/users/mismatches", func(w http.ResponseWriter, r *http.Request) {
		fr.mu.Lock()
		status := fr.status
		out := mismatchesResponse{Mismatches: append([]mismatchRow(nil), fr.mismatches...)}
		fr.mu.Unlock()
		if status != 0 && status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})

	mux.HandleFunc("GET /api/audit", func(w http.ResponseWriter, r *http.Request) {
		fr.mu.Lock()
		fr.auditHits++
		fr.lastAuditQuery = r.URL.Query()
		status := fr.status
		out := auditQueryResponse{Events: append([]auditEventWire(nil), fr.auditEvents...)}
		fr.mu.Unlock()
		if status != 0 && status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})

	mux.HandleFunc("GET /api/manifest", func(w http.ResponseWriter, r *http.Request) {
		fr.mu.Lock()
		fr.manifestHits++
		status := fr.status
		m := fr.schema
		fr.mu.Unlock()
		if status != 0 && status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(m)
	})
	mux.HandleFunc("GET /api/{entity}", func(w http.ResponseWriter, r *http.Request) {
		fr.mu.Lock()
		fr.lastListQuery = r.URL.Query()
		status := fr.status
		recs := append([]recordWire(nil), fr.records[r.PathValue("entity")]...)
		fr.mu.Unlock()
		if status != 0 && status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Records []recordWire `json:"records"`
			Limit   int          `json:"limit"`
			Offset  int          `json:"offset"`
		}{Records: recs, Limit: 50, Offset: 0})
	})
	mux.HandleFunc("GET /api/{entity}/{id}", func(w http.ResponseWriter, r *http.Request) {
		fr.mu.Lock()
		status := fr.status
		var fields map[string]string
		for _, rec := range fr.records[r.PathValue("entity")] {
			if rec.ID == r.PathValue("id") {
				fields = rec.Fields
			}
		}
		fr.mu.Unlock()
		if status != 0 && status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		if fields == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(fields)
	})

	mux.HandleFunc("POST /api/reviews", func(w http.ResponseWriter, r *http.Request) {
		fr.mu.Lock()
		subjects := make([]review.Item, len(fr.users))
		for i, u := range fr.users {
			subjects[i] = review.Item{Email: u.Email, RolesAtReview: u.Roles}
		}
		fr.mu.Unlock()
		rv, err := fr.reviews.Create(r.Context(), "boss@client.example", subjects)
		if err != nil {
			writeReviewErr(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rv)
	})
	mux.HandleFunc("GET /api/reviews", func(w http.ResponseWriter, r *http.Request) {
		list, _ := fr.reviews.List(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Reviews []review.Review `json:"reviews"`
		}{Reviews: list})
	})
	mux.HandleFunc("GET /api/reviews/{id}", func(w http.ResponseWriter, r *http.Request) {
		rv, err := fr.reviews.Get(r.Context(), r.PathValue("id"))
		if err != nil {
			writeReviewErr(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rv)
	})
	mux.HandleFunc("POST /api/reviews/{id}/decisions", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Email    string `json:"email"`
			Decision string `json:"decision"`
			Note     string `json:"note"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if err := fr.reviews.Decide(r.Context(), r.PathValue("id"), body.Email, review.Decision(body.Decision), body.Note); err != nil {
			writeReviewErr(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /api/reviews/{id}/complete", func(w http.ResponseWriter, r *http.Request) {
		rv, err := fr.reviews.Complete(r.Context(), r.PathValue("id"))
		if err != nil {
			writeReviewErr(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rv)
	})

	record := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		fr.mu.Lock()
		status := fr.status
		fr.mutations = append(fr.mutations, recordedMutation{
			Method: r.Method,
			Path:   r.URL.Path,
			Auth:   r.Header.Get("Authorization"),
			Body:   strings.TrimSpace(string(body)),
		})
		fr.mu.Unlock()
		if status != 0 && status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
	mux.HandleFunc("POST /api/users", record)
	mux.HandleFunc("DELETE /api/users/{email}", record)
	mux.HandleFunc("POST /api/users/{email}/roles", record)
	mux.HandleFunc("DELETE /api/users/{email}/roles", record)

	fr.Server = httptest.NewServer(mux)
	t.Cleanup(fr.Close)
	return fr
}

// usersResponse and mismatchesResponse mirror the remote API's wire
// envelopes for the Users & roles reads, so the fake serves the same JSON
// shape the dashboard's client decodes.
type usersResponse struct {
	Users []userRow `json:"users"`
}

type mismatchesResponse struct {
	Mismatches []mismatchRow `json:"mismatches"`
}

// auditQueryResponse mirrors the remote API's GET /api/audit envelope.
type auditQueryResponse struct {
	Events []auditEventWire `json:"events"`
}

// writeReviewErr maps a review store error to the HTTP status the real
// server's writeGateError produces, so the fake's review endpoints behave
// like the remote.
func writeReviewErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, review.ErrNotFound), errors.Is(err, review.ErrSubjectNotFound):
		w.WriteHeader(http.StatusNotFound)
	case errors.Is(err, review.ErrClosed):
		w.WriteHeader(http.StatusConflict)
	case errors.Is(err, review.ErrInvalidDecision), errors.Is(err, review.ErrEmptyReview):
		w.WriteHeader(http.StatusBadRequest)
	default:
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func newTestServer(t *testing.T, remote string, tokens TokenSource) *Server {
	t.Helper()
	s, err := New(Config{Addr: "127.0.0.1:0", RemoteURL: remote, Tokens: tokens})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func loopbackGet(path string) *http.Request {
	return httptest.NewRequest(http.MethodGet, "http://127.0.0.1:7777"+path, nil)
}

// The dashboard serves its overview shell on loopback and renders the
// signed-in principal server-side — proof of SSR plus a live
// authenticated read against the remote (criterion ONt).
func TestServesIndexOnLoopback(t *testing.T) {
	fr := newFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok-123"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/"))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if body := rec.Body.String(); !strings.Contains(body, "boss@client.example") {
		t.Errorf("index did not render the principal email server-side; body:\n%s", body)
	}
}

// The overview renders the briefing server-side: system status, the
// deployment tier, and the record/user counts the remote API reported.
func TestIndexRendersOverviewStatusTierAndCounts(t *testing.T) {
	fr := newFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok-123"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/"))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"operational",       // system status
		"unknown (Phase 6",  // deployment tier placeholder (the "+" is HTML-escaped)
		"5",                 // total records
		"3",                 // authorized users
		"patient", "doctor", // per-entity breakdown
	} {
		if !strings.Contains(body, want) {
			t.Errorf("overview body missing %q; body:\n%s", want, body)
		}
	}
}

// The needs-attention panel surfaces an IdP mismatch — a suspended
// account still holding a role — so the auditor sees it without leaving
// the overview.
func TestIndexShowsIdPMismatchInNeedsAttention(t *testing.T) {
	fr := newFakeRemote(t)
	fr.overview.NeedsAttention.IdPMismatches = []overviewMismatch{
		{Email: "gone@client.example", Roles: []string{"user"}, Status: "suspended"},
	}
	s := newTestServer(t, fr.URL, staticToken{token: "tok-123"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/"))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "gone@client.example") {
		t.Errorf("needs-attention panel did not surface the mismatched account; body:\n%s", body)
	}
	if !strings.Contains(body, "suspended") {
		t.Errorf("needs-attention panel did not show the mismatch status; body:\n%s", body)
	}
}

// Recent activity renders as a table of bounded audit metadata — actor,
// action, resource, outcome — and never a field value.
func TestIndexRendersRecentActivity(t *testing.T) {
	fr := newFakeRemote(t)
	fr.overview.RecentActivity = []overviewEvent{{
		Time:     time.Date(2026, 5, 19, 14, 30, 5, 0, time.UTC),
		Kind:     "access",
		Outcome:  "allowed",
		Actor:    overviewActor{Type: "user", ID: "u@client.example", Email: "u@client.example"},
		Action:   "read",
		Resource: overviewResource{Entity: "patient", ID: "p1"},
	}}
	s := newTestServer(t, fr.URL, staticToken{token: "tok-123"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/"))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"2026-05-19 14:30:05", "u@client.example", "read", "patient/p1", "allowed"} {
		if !strings.Contains(body, want) {
			t.Errorf("recent-activity table missing %q; body:\n%s", want, body)
		}
	}
}

// The overview is fetched server-side from the remote API carrying the
// cached bearer token — the same backend-for-frontend property the whoami
// read has, now proven for the overview read too.
func TestIndexOverviewCarriesBearerToken(t *testing.T) {
	fr := newFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok-123"})

	s.Handler().ServeHTTP(httptest.NewRecorder(), loopbackGet("/"))

	if fr.overviewHits == 0 {
		t.Fatal("dashboard did not call /api/overview to render the overview")
	}
	if fr.overviewAuth != "Bearer tok-123" {
		t.Errorf("overview Authorization = %q, want Bearer tok-123", fr.overviewAuth)
	}
}

// Every data read flows through the remote API carrying the cached
// bearer token; the dashboard never touches a database (criterion IK2).
func TestIndexFetchesFromRemoteAPI(t *testing.T) {
	fr := newFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok-123"})

	s.Handler().ServeHTTP(httptest.NewRecorder(), loopbackGet("/"))

	if fr.hits == 0 {
		t.Fatal("dashboard did not call the remote API to render /")
	}
	if fr.lastPath != "/api/whoami" {
		t.Errorf("remote path = %q, want /api/whoami", fr.lastPath)
	}
	if fr.lastAuth != "Bearer tok-123" {
		t.Errorf("Authorization = %q, want Bearer tok-123", fr.lastAuth)
	}
}

// A request bearing a non-loopback Host is refused: a local server on a
// known port is otherwise reachable from any web page the admin visits
// (DNS-rebinding / CSRF). The Host allowlist is the cheap first defense.
func TestRejectsNonLoopbackHost(t *testing.T) {
	fr := newFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok-123"})

	req := loopbackGet("/")
	req.Host = "evil.example"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("non-loopback Host = %d, want 403", rec.Code)
	}
}

func TestAllowsLocalhostHost(t *testing.T) {
	fr := newFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok-123"})

	req := loopbackGet("/")
	req.Host = "localhost:7777"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("localhost Host = %d, want 200", rec.Code)
	}
}

// With no cached credential the overview renders a sign-in page that
// tells the operator to run `kura login`, and crucially does not reach
// the remote with an empty token.
func TestRendersSignInWhenNoToken(t *testing.T) {
	fr := newFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{err: errors.New("no cached credential")})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/"))

	if rec.Code != http.StatusOK {
		t.Fatalf("sign-in page = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "kura login") {
		t.Errorf("sign-in page does not mention `kura login`; body:\n%s", rec.Body.String())
	}
	if fr.hits != 0 {
		t.Error("dashboard called the remote despite having no token to send")
	}
}

// A 401 from the remote (an expired token) lands on the same sign-in
// prompt rather than a stack trace.
func TestRendersSignInOnRemote401(t *testing.T) {
	fr := newFakeRemote(t)
	fr.status = http.StatusUnauthorized
	s := newTestServer(t, fr.URL, staticToken{token: "stale"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/"))

	if rec.Code != http.StatusOK {
		t.Fatalf("expired-token page = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "kura login") {
		t.Errorf("expired-token page does not prompt re-login; body:\n%s", rec.Body.String())
	}
}

func TestServesStaticCSS(t *testing.T) {
	fr := newFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/static/app.css"))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /static/app.css = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "css") {
		t.Errorf("Content-Type = %q, want a CSS type", ct)
	}
	if rec.Body.Len() == 0 {
		t.Error("app.css served empty")
	}
}

// The cached bearer token stays server-side: it must never appear in the
// HTML the browser receives. This is the security property the BFF model
// buys — the browser talks only to loopback and never holds the token.
func TestDoesNotLeakTokenToBrowser(t *testing.T) {
	fr := newFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "super-secret-token"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/"))

	if strings.Contains(rec.Body.String(), "super-secret-token") {
		t.Error("the cached bearer token leaked into the dashboard HTML")
	}
}

func TestNewRequiresRemoteURLAndTokens(t *testing.T) {
	if _, err := New(Config{Addr: "127.0.0.1:0", Tokens: staticToken{}}); err == nil {
		t.Error("New accepted a Config with no RemoteURL")
	}
	if _, err := New(Config{Addr: "127.0.0.1:0", RemoteURL: "http://x"}); err == nil {
		t.Error("New accepted a Config with no TokenSource")
	}
}
