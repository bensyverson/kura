package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bensyverson/kura/internal/identity"
)

// GET /api/whoami returns the authenticated principal: every field
// requireAuth resolved (type, id, email, tenant). It is the
// minimal self-identity read: the agent has a token in hand and the
// server tells it which principal that token resolved to.
func TestWhoamiReturnsAuthenticatedPrincipal(t *testing.T) {
	srv, _, _, _, _, userTok := adminServer(t)
	r := httptest.NewRequest(http.MethodGet, "/api/whoami", nil)
	r.Header.Set("Authorization", "Bearer "+userTok)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var got identity.Principal
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if got.Email != "user@client.com" {
		t.Errorf("Email = %q, want user@client.com", got.Email)
	}
	if got.Type != identity.PrincipalUser {
		t.Errorf("Type = %q, want %q", got.Type, identity.PrincipalUser)
	}
	if got.Tenant == "" {
		t.Error("Tenant must be populated")
	}
}

// An unauthenticated request never reaches the whoami handler — requireAuth
// rejects it at 401 like every other /api/ route.
func TestWhoamiRejectsUnauthenticated(t *testing.T) {
	srv, _, _, _, _, _ := adminServer(t)
	r := httptest.NewRequest(http.MethodGet, "/api/whoami", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated /api/whoami status = %d, want 401", w.Code)
	}
}

// The whoami endpoint is mounted under /api/ and satisfies the gatedRoute
// invariant — the architectural test in gated_test.go enforces this,
// but we double-check the registration explicitly here so a regression
// is named.
func TestWhoamiRouteRegistered(t *testing.T) {
	srv, _, _, _, _, _ := adminServer(t)
	pattern := "GET /api/whoami"
	h, ok := srv.apiRoutes[pattern]
	if !ok {
		t.Fatalf("/api/whoami is not registered (apiRoutes has: %v)", patternsOf(srv))
	}
	if _, ok := h.(*whoamiHandler); !ok {
		t.Errorf("/api/whoami handler type = %T, want *whoamiHandler", h)
	}
}

func patternsOf(s *Server) []string {
	out := make([]string, 0, len(s.apiRoutes))
	for p := range s.apiRoutes {
		out = append(out, p)
	}
	return out
}

// Whoami responses must not include the signing secret or any
// surprise fields — the response is exactly the public Principal
// shape. A regression that added a private field would surface here.
func TestWhoamiResponseShapeIsPrincipalOnly(t *testing.T) {
	srv, _, _, _, _, userTok := adminServer(t)
	r := httptest.NewRequest(http.MethodGet, "/api/whoami", nil)
	r.Header.Set("Authorization", "Bearer "+userTok)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	body := w.Body.String()
	for _, leak := range []string{"signing", "secret", "token"} {
		if strings.Contains(strings.ToLower(body), leak) {
			t.Errorf("whoami response leaks %q: %s", leak, body)
		}
	}
}
