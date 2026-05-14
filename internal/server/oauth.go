package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/identity"
)

// defaultStateTTL bounds how long an in-flight OAuth login may sit
// between /oauth/login and /oauth/callback before its state expires.
const defaultStateTTL = 10 * time.Minute

// WorkspaceIdentity is a verified Google Workspace identity: the email
// and the `hd` hosted-domain claim, taken from a validated id_token. It
// is what the OAuth layer hands to DomainTrust to resolve a principal.
type WorkspaceIdentity struct {
	Email  string
	Domain string
}

// GoogleAuthenticator is the seam over the Google side of the OAuth
// flow. The real implementation builds the consent URL, exchanges the
// auth code, and verifies the id_token; a fake stands in for it in tests
// so the handler logic is testable without a live Workspace domain.
type GoogleAuthenticator interface {
	// AuthCodeURL returns the Google consent-screen URL for state.
	AuthCodeURL(state string) string
	// Exchange swaps an auth code for a verified Workspace identity.
	Exchange(ctx context.Context, code string) (WorkspaceIdentity, error)
}

// loginState is one in-flight login: the CLI loopback URL the minted
// token must be delivered to, and the moment the state expires.
type loginState struct {
	redirect string
	expires  time.Time
}

// stateStore holds in-flight OAuth states. v1 kura serve is
// single-instance, so an in-memory store is correct; a multi-instance
// deployment would need a shared store, a later and separate concern.
type stateStore struct {
	mu     sync.Mutex
	states map[string]loginState
	ttl    time.Duration
	now    func() time.Time
}

// newStateStore returns an empty state store whose entries live for ttl.
func newStateStore(ttl time.Duration) *stateStore {
	return &stateStore{
		states: make(map[string]loginState),
		ttl:    ttl,
		now:    time.Now,
	}
}

// put records that state maps to the CLI loopback redirect.
func (s *stateStore) put(state, redirect string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[state] = loginState{redirect: redirect, expires: s.now().Add(s.ttl)}
}

// take returns the redirect for state and removes it — state is
// single-use. A missing or expired state returns ok == false.
func (s *stateStore) take(state string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ls, ok := s.states[state]
	if !ok {
		return "", false
	}
	delete(s.states, state)
	if s.now().After(ls.expires) {
		return "", false
	}
	return ls.redirect, true
}

// oauthHandler serves the two public OAuth endpoints: /oauth/login,
// which sends the browser to Google, and /oauth/callback, which Google
// redirects back to. The callback is the only point that mints a Kura
// token — it does so only after a verified identity resolves to a
// trusted principal.
type oauthHandler struct {
	google   GoogleAuthenticator
	trust    identity.DomainTrust
	auth     *identity.Authenticator
	recorder *audit.Recorder
	states   *stateStore
	tokenTTL time.Duration
	logger   *slog.Logger
}

// newOAuthHandler assembles an oauthHandler. tokenTTL is the lifetime of
// the Kura tokens it mints.
func newOAuthHandler(g GoogleAuthenticator, trust identity.DomainTrust, auth *identity.Authenticator, rec *audit.Recorder, tokenTTL time.Duration, logger *slog.Logger) *oauthHandler {
	return &oauthHandler{
		google:   g,
		trust:    trust,
		auth:     auth,
		recorder: rec,
		states:   newStateStore(defaultStateTTL),
		tokenTTL: tokenTTL,
		logger:   logger,
	}
}

// login starts the flow. The CLI calls it with ?redirect set to its own
// loopback URL; login refuses any non-loopback target — delivering a
// token to an arbitrary host would be a token leak — stores the target
// under a fresh state, and redirects the browser to Google.
func (h *oauthHandler) login(w http.ResponseWriter, r *http.Request) {
	redirect := r.URL.Query().Get("redirect")
	if redirect == "" {
		http.Error(w, "redirect is required", http.StatusBadRequest)
		return
	}
	if !isLoopbackURL(redirect) {
		http.Error(w, "redirect must be a loopback address", http.StatusBadRequest)
		return
	}
	state, err := randState()
	if err != nil {
		h.logger.Error("oauth: generating state", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.states.put(state, redirect)
	http.Redirect(w, r, h.google.AuthCodeURL(state), http.StatusFound)
}

// callback completes the flow. Google redirects the browser here with a
// code and the state from login. callback exchanges the code for a
// verified identity, resolves it to a trusted principal, mints a Kura
// token, records the authentication, and redirects the browser back to
// the CLI's loopback URL with the token attached. Every failure path
// records a denied authentication and delivers no token.
func (h *oauthHandler) callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	redirect, ok := h.states.take(q.Get("state"))
	if !ok {
		// No state means no trusted record of who started this flow or
		// where a token should go. There is nothing safe to do and
		// nobody to attribute a denial to.
		http.Error(w, "unknown or expired login state", http.StatusBadRequest)
		return
	}

	wid, err := h.google.Exchange(ctx, q.Get("code"))
	if err != nil {
		h.denyAuthentication(ctx, w, "code exchange failed", err)
		return
	}

	principal, err := h.trust.Principal(wid.Email, wid.Domain)
	if err != nil {
		h.denyAuthentication(ctx, w, "untrusted identity", err)
		return
	}

	token, err := h.auth.Issue(principal, h.tokenTTL)
	if err != nil {
		h.denyAuthentication(ctx, w, "issuing token", err)
		return
	}

	if err := h.recorder.RecordAuthentication(ctx, principal, audit.OutcomeAllowed); err != nil {
		// Fail closed: an authentication Kura cannot record is one it
		// does not complete.
		h.logger.Error("oauth: recording authentication", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, withToken(redirect, token), http.StatusFound)
}

// denyAuthentication records a failed authentication against the zero
// principal and returns a 401 without a token. The reason is logged, not
// returned — the browser learns the login failed, nothing more.
func (h *oauthHandler) denyAuthentication(ctx context.Context, w http.ResponseWriter, reason string, cause error) {
	h.logger.Warn("oauth: authentication denied", "reason", reason, "err", cause)
	if err := h.recorder.RecordAuthentication(ctx, identity.Principal{}, audit.OutcomeDenied); err != nil {
		h.logger.Error("oauth: recording denied authentication", "err", err)
	}
	http.Error(w, "authentication failed", http.StatusUnauthorized)
}

// isLoopbackURL reports whether raw is an http URL pointing at the local
// loopback interface — the only kind of target /oauth/login will deliver
// a token to.
func isLoopbackURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" {
		return false
	}
	switch u.Hostname() {
	case "127.0.0.1", "localhost", "::1":
		return true
	default:
		return false
	}
}

// withToken returns redirect with the minted token added as a query
// parameter, preserving any parameters the CLI already put there (its
// own loopback-leg state, for one).
func withToken(redirect, token string) string {
	u, err := url.Parse(redirect)
	if err != nil {
		return redirect
	}
	q := u.Query()
	q.Set("token", token)
	u.RawQuery = q.Encode()
	return u.String()
}

// randState returns a cryptographically random, URL-safe state value.
func randState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
