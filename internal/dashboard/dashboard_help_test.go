package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The programmatic-access page documents all three machine surfaces — the
// CLI, the HTTP API, and the MCP server — plus the token-issuance flow, so
// an operator can drive Kura without the dashboard.
func TestHelpPageDocumentsCLIAPIAndMCP(t *testing.T) {
	fr := newFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/help"))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /help = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"kura login",            // the token-issuance flow
		"token",                 // the bearer token concept
		"Authorization: Bearer", // HTTP API auth
		"/api/",                 // the HTTP API surface
		"kura mcp",              // the MCP server
		"agent-context",         // agent introspection
	} {
		if !strings.Contains(body, want) {
			t.Errorf("programmatic-access page missing %q; body:\n%s", want, body)
		}
	}
}

// The page shows the operator's configured server URL so its examples are
// concrete (the `kura login --server` target and the API base), and never
// the bearer token.
func TestHelpPageShowsServerURLNotToken(t *testing.T) {
	fr := newFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "super-secret"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/help"))

	body := rec.Body.String()
	if !strings.Contains(body, fr.URL) {
		t.Errorf("help page did not show the configured server URL %q; body:\n%s", fr.URL, body)
	}
	if strings.Contains(body, "super-secret") {
		t.Error("the bearer token leaked into the programmatic-access page")
	}
}
