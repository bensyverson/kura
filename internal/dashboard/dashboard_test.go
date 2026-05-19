package dashboard

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/bensyverson/kura/internal/identity"
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
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/whoami", func(w http.ResponseWriter, r *http.Request) {
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
	fr.Server = httptest.NewServer(mux)
	t.Cleanup(fr.Close)
	return fr
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
