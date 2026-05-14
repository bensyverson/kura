package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/identity"
)

// discardLogger is a slog.Logger that drops everything — request and
// auth telemetry is not what these tests are asserting on.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeGoogle stands in for the real Google OAuth client so the handler
// logic is testable without a live Workspace domain.
type fakeGoogle struct {
	consentURL  string
	identity    WorkspaceIdentity
	exchangeErr error
}

func (f *fakeGoogle) AuthCodeURL(state string) string {
	return f.consentURL + "?state=" + url.QueryEscape(state)
}

func (f *fakeGoogle) Exchange(_ context.Context, _ string) (WorkspaceIdentity, error) {
	if f.exchangeErr != nil {
		return WorkspaceIdentity{}, f.exchangeErr
	}
	return f.identity, nil
}

func testTrust() identity.DomainTrust {
	return identity.DomainTrust{
		FirmDomain:    "examplefirm.com",
		ClientDomains: []string{"client.example"},
		AdminEmails:   []string{"boss@client.example"},
	}
}

// oauthFixture wires an oauthHandler over fakes and returns the handler
// plus the collaborators a test needs to inspect.
func oauthFixture(t *testing.T, g GoogleAuthenticator) (*oauthHandler, *identity.Authenticator, *audit.MemStore) {
	t.Helper()
	auth := identity.NewAuthenticator([]byte("test-signing-secret"))
	store := audit.NewMemStore()
	rec := audit.NewRecorder(store)
	h := newOAuthHandler(g, testTrust(), auth, rec, time.Hour, discardLogger())
	return h, auth, store
}

// /oauth/login must redirect the browser to Google and remember the
// CLI's loopback target under the state it hands Google, so the callback
// can find it again.
func TestOAuthLoginRedirectsToGoogleAndStoresState(t *testing.T) {
	g := &fakeGoogle{consentURL: "https://accounts.google.example/o/oauth2/auth"}
	h, _, _ := oauthFixture(t, g)

	loopback := "http://127.0.0.1:5555/callback?state=cli-state"
	req := httptest.NewRequest(http.MethodGet, "/oauth/login?redirect="+url.QueryEscape(loopback), nil)
	rec := httptest.NewRecorder()
	h.login(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("Location is not a URL: %v", err)
	}
	if !strings.HasPrefix(loc.String(), g.consentURL) {
		t.Errorf("did not redirect to Google: %s", loc)
	}
	state := loc.Query().Get("state")
	if state == "" {
		t.Fatal("no state passed to Google")
	}
	got, ok := h.states.take(state)
	if !ok {
		t.Fatal("state passed to Google was not stored")
	}
	if got != loopback {
		t.Errorf("stored redirect = %q, want %q", got, loopback)
	}
}

// /oauth/login must refuse to deliver a token anywhere but a loopback
// address — a token redirect to an arbitrary host is a token leak.
func TestOAuthLoginRejectsNonLoopbackRedirect(t *testing.T) {
	h, _, _ := oauthFixture(t, &fakeGoogle{consentURL: "https://accounts.google.example/auth"})

	req := httptest.NewRequest(http.MethodGet, "/oauth/login?redirect="+url.QueryEscape("https://evil.example/steal"), nil)
	rec := httptest.NewRecorder()
	h.login(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for non-loopback redirect", rec.Code)
	}
}

// /oauth/login with no redirect target is a malformed request.
func TestOAuthLoginRequiresRedirect(t *testing.T) {
	h, _, _ := oauthFixture(t, &fakeGoogle{consentURL: "https://accounts.google.example/auth"})

	req := httptest.NewRequest(http.MethodGet, "/oauth/login", nil)
	rec := httptest.NewRecorder()
	h.login(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 when redirect is missing", rec.Code)
	}
}

// /oauth/callback completes the flow: it exchanges the code, maps the
// verified domain to a principal, mints a Kura token, records the
// authentication, and hands the token back to the CLI's loopback URL.
func TestOAuthCallbackMintsTokenAndRedirectsToLoopback(t *testing.T) {
	g := &fakeGoogle{identity: WorkspaceIdentity{Email: "alex@examplefirm.com", Domain: "examplefirm.com"}}
	h, auth, store := oauthFixture(t, g)

	h.states.put("server-state", "http://127.0.0.1:5555/callback?state=cli-state")
	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?code=good-code&state=server-state", nil)
	rec := httptest.NewRecorder()
	h.callback(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("Location is not a URL: %v", err)
	}
	if loc.Hostname() != "127.0.0.1" || loc.Query().Get("state") != "cli-state" {
		t.Errorf("did not redirect back to the CLI loopback target: %s", loc)
	}
	token := loc.Query().Get("token")
	if token == "" {
		t.Fatal("no token delivered to the loopback target")
	}
	principal, err := auth.Resolve(token)
	if err != nil {
		t.Fatalf("delivered token does not resolve: %v", err)
	}
	if principal.Type != identity.PrincipalConsultant || principal.Email != "alex@examplefirm.com" {
		t.Errorf("token resolved to the wrong principal: %+v", principal)
	}

	events, _ := store.Query(context.Background(), audit.Filter{})
	if len(events) != 1 || events[0].Kind != audit.KindAuthentication || events[0].Outcome != audit.OutcomeAllowed {
		t.Errorf("expected one allowed authentication event, got %+v", events)
	}
}

// A callback whose state is unknown (forged, or already consumed) yields
// no token.
func TestOAuthCallbackRejectsUnknownState(t *testing.T) {
	g := &fakeGoogle{identity: WorkspaceIdentity{Email: "alex@examplefirm.com", Domain: "examplefirm.com"}}
	h, _, _ := oauthFixture(t, g)

	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?code=good-code&state=never-issued", nil)
	rec := httptest.NewRecorder()
	h.callback(rec, req)

	if rec.Code == http.StatusFound {
		t.Errorf("callback with an unknown state delivered a token (status %d, Location %q)", rec.Code, rec.Header().Get("Location"))
	}
}

// State is single-use: a replayed callback for an already-consumed state
// is rejected.
func TestOAuthCallbackStateIsSingleUse(t *testing.T) {
	g := &fakeGoogle{identity: WorkspaceIdentity{Email: "alex@examplefirm.com", Domain: "examplefirm.com"}}
	h, _, _ := oauthFixture(t, g)

	h.states.put("server-state", "http://127.0.0.1:5555/callback")
	first := httptest.NewRequest(http.MethodGet, "/oauth/callback?code=good-code&state=server-state", nil)
	h.callback(httptest.NewRecorder(), first)

	replay := httptest.NewRequest(http.MethodGet, "/oauth/callback?code=good-code&state=server-state", nil)
	rec := httptest.NewRecorder()
	h.callback(rec, replay)
	if rec.Code == http.StatusFound {
		t.Error("a replayed callback for a consumed state delivered a token")
	}
}

// A verified identity on a domain the deployment does not trust gets no
// token, and the failed authentication is recorded.
func TestOAuthCallbackRejectsUntrustedDomain(t *testing.T) {
	g := &fakeGoogle{identity: WorkspaceIdentity{Email: "mallory@evil.example", Domain: "evil.example"}}
	h, _, store := oauthFixture(t, g)

	h.states.put("server-state", "http://127.0.0.1:5555/callback")
	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?code=good-code&state=server-state", nil)
	rec := httptest.NewRecorder()
	h.callback(rec, req)

	if rec.Code == http.StatusFound {
		t.Errorf("untrusted domain was issued a token (Location %q)", rec.Header().Get("Location"))
	}
	events, _ := store.Query(context.Background(), audit.Filter{})
	if len(events) != 1 || events[0].Kind != audit.KindAuthentication || events[0].Outcome != audit.OutcomeDenied {
		t.Errorf("expected one denied authentication event, got %+v", events)
	}
}

// A code-exchange failure (Google rejects the code) yields no token and
// records a denied authentication.
func TestOAuthCallbackRecordsFailedExchange(t *testing.T) {
	g := &fakeGoogle{exchangeErr: errors.New("invalid_grant")}
	h, _, store := oauthFixture(t, g)

	h.states.put("server-state", "http://127.0.0.1:5555/callback")
	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?code=bad-code&state=server-state", nil)
	rec := httptest.NewRecorder()
	h.callback(rec, req)

	if rec.Code == http.StatusFound {
		t.Error("a failed code exchange delivered a token")
	}
	events, _ := store.Query(context.Background(), audit.Filter{})
	if len(events) != 1 || events[0].Outcome != audit.OutcomeDenied {
		t.Errorf("expected one denied authentication event, got %+v", events)
	}
}

// An expired state is not honored.
func TestStateStoreExpiry(t *testing.T) {
	s := newStateStore(time.Hour)
	now := time.Now()
	s.now = func() time.Time { return now }
	s.put("s1", "http://127.0.0.1:5555/cb")

	s.now = func() time.Time { return now.Add(2 * time.Hour) }
	if _, ok := s.take("s1"); ok {
		t.Error("an expired state was honored")
	}
}
