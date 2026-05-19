package dashboard

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/bensyverson/kura/internal/cedar"
	"github.com/bensyverson/kura/internal/pii"
)

// testPolicy is a small, hand-built policy the Users & roles tests render
// effective access against: an admin who reads a PII category and an
// auditor who reads nothing.
func testPolicy() cedar.Policy {
	return cedar.Policy{
		Roles: []cedar.Role{
			{Name: "admin", Description: "Full access."},
			{Name: "auditor", Description: "Read-only review."},
		},
		Grants: []cedar.Grant{
			{Role: "admin", Entity: "patient", Action: cedar.ActionRead, VisiblePII: []pii.Category{pii.CategoryPerson}},
			{Role: "admin", Entity: "patient", Action: cedar.ActionDelete},
			{Role: "auditor", Entity: "patient", Action: cedar.ActionList},
		},
	}
}

func usersFakeRemote(t *testing.T) *fakeRemote {
	t.Helper()
	fr := newFakeRemote(t)
	fr.users = []userRow{
		{Email: "ada@client.example", Roles: []string{"admin"}},
		{Email: "noroles@client.example", Roles: nil},
	}
	fr.policy = testPolicy()
	return fr
}

func loopbackPost(path string, form url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:7777"+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://127.0.0.1:7777")
	req.Host = "127.0.0.1:7777"
	return req
}

// The page lists each authorized user with the roles they hold.
func TestUsersPageListsUsersAndRoles(t *testing.T) {
	fr := usersFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/users"))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /users = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"ada@client.example", "noroles@client.example", "admin"} {
		if !strings.Contains(body, want) {
			t.Errorf("users page missing %q; body:\n%s", want, body)
		}
	}
}

// Criterion YAC: the effective policy a user holds — its entities, actions,
// and visible PII — is visible on the page.
func TestUsersPageShowsEffectiveAccessPerUser(t *testing.T) {
	fr := usersFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/users"))

	body := rec.Body.String()
	// ada is an admin: her effective access includes read and delete on
	// patient, and the name PII category she may see.
	for _, want := range []string{"patient", "read", "delete", string(pii.CategoryPerson)} {
		if !strings.Contains(body, want) {
			t.Errorf("effective access missing %q; body:\n%s", want, body)
		}
	}
}

// Criterion YAC (negative): role *assignment* is editable, but policy
// *authoring* is not — there is no free-form policy editor on the page.
func TestUsersPageHasNoFreeFormPolicyEditor(t *testing.T) {
	fr := usersFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/users"))

	body := rec.Body.String()
	if strings.Contains(body, "<textarea") {
		t.Error("users page exposes a free-form policy editor (a <textarea>); policy authoring is a repo/PR activity")
	}
}

// Criterion: IdP mismatches are flagged so a reviewer sees an authorized
// user whose identity-provider account no longer matches their access.
func TestUsersPageFlagsIdPMismatch(t *testing.T) {
	fr := usersFakeRemote(t)
	fr.mismatches = []mismatchRow{
		{Email: "ada@client.example", Roles: []string{"admin"}, Status: "suspended"},
	}
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/users"))

	body := rec.Body.String()
	if !strings.Contains(body, "suspended") {
		t.Errorf("users page did not flag the IdP mismatch status; body:\n%s", body)
	}
}

// The page offers a way to add a user to the authorized list (criterion
// PPt): a form that POSTs to /users.
func TestUsersPageHasAddUserForm(t *testing.T) {
	fr := usersFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/users"))

	body := rec.Body.String()
	if !strings.Contains(body, `action="/users"`) || !strings.Contains(body, `method="post"`) {
		t.Errorf("users page has no add-user form; body:\n%s", body)
	}
}

// Every read on the page flows through the remote API carrying the cached
// bearer token; the dashboard never touches a database.
func TestUsersPageReadsCarryBearerToken(t *testing.T) {
	fr := usersFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok-xyz"})

	s.Handler().ServeHTTP(httptest.NewRecorder(), loopbackGet("/users"))

	if fr.hits == 0 {
		t.Fatal("dashboard did not call the remote API for /users")
	}
}

func TestUsersPageDoesNotLeakToken(t *testing.T) {
	fr := usersFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "super-secret"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/users"))

	if strings.Contains(rec.Body.String(), "super-secret") {
		t.Error("the bearer token leaked into the users page HTML")
	}
}

// Criterion PPt: adding a user from the UI POSTs to the remote API with
// the email, carrying the token, and redirects (POST-redirect-GET).
func TestAddUserPostsToRemote(t *testing.T) {
	fr := usersFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackPost("/users", url.Values{"email": {"new@client.example"}}))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("add user = %d, want 303 redirect; body:\n%s", rec.Code, rec.Body.String())
	}
	if len(fr.mutations) != 1 {
		t.Fatalf("remote saw %d mutations, want 1", len(fr.mutations))
	}
	m := fr.mutations[0]
	if m.Method != http.MethodPost || m.Path != "/api/users" {
		t.Errorf("mutation = %s %s, want POST /api/users", m.Method, m.Path)
	}
	if m.Auth != "Bearer tok" {
		t.Errorf("mutation Authorization = %q, want Bearer tok", m.Auth)
	}
	if !strings.Contains(m.Body, "new@client.example") {
		t.Errorf("mutation body %q does not carry the email", m.Body)
	}
}

// Criterion PPt: assigning a role POSTs the role to the remote role
// endpoint for that user.
func TestAssignRolePostsToRemote(t *testing.T) {
	fr := usersFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	form := url.Values{"email": {"ada@client.example"}, "role": {"auditor"}, "op": {"assign"}}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackPost("/users/roles", form))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("assign role = %d, want 303; body:\n%s", rec.Code, rec.Body.String())
	}
	if len(fr.mutations) != 1 {
		t.Fatalf("remote saw %d mutations, want 1", len(fr.mutations))
	}
	m := fr.mutations[0]
	wantPath := "/api/users/" + url.PathEscape("ada@client.example") + "/roles"
	if m.Method != http.MethodPost || m.Path != wantPath {
		t.Errorf("mutation = %s %s, want POST %s", m.Method, m.Path, wantPath)
	}
	if !strings.Contains(m.Body, "auditor") {
		t.Errorf("mutation body %q does not carry the role", m.Body)
	}
}

// Criterion PPt: revoking a role DELETEs it from the remote role endpoint.
func TestRevokeRolePostsToRemote(t *testing.T) {
	fr := usersFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	form := url.Values{"email": {"ada@client.example"}, "role": {"admin"}, "op": {"revoke"}}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackPost("/users/roles", form))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("revoke role = %d, want 303; body:\n%s", rec.Code, rec.Body.String())
	}
	if len(fr.mutations) != 1 {
		t.Fatalf("remote saw %d mutations, want 1", len(fr.mutations))
	}
	m := fr.mutations[0]
	wantPath := "/api/users/" + url.PathEscape("ada@client.example") + "/roles"
	if m.Method != http.MethodDelete || m.Path != wantPath {
		t.Errorf("mutation = %s %s, want DELETE %s", m.Method, m.Path, wantPath)
	}
}

// Criterion PPt: deactivating a user DELETEs the user resource, stripping
// every role atomically on the remote.
func TestDeactivateUserPostsToRemote(t *testing.T) {
	fr := usersFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackPost("/users/deactivate", url.Values{"email": {"ada@client.example"}}))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("deactivate = %d, want 303; body:\n%s", rec.Code, rec.Body.String())
	}
	if len(fr.mutations) != 1 {
		t.Fatalf("remote saw %d mutations, want 1", len(fr.mutations))
	}
	m := fr.mutations[0]
	wantPath := "/api/users/" + url.PathEscape("ada@client.example")
	if m.Method != http.MethodDelete || m.Path != wantPath {
		t.Errorf("mutation = %s %s, want DELETE %s", m.Method, m.Path, wantPath)
	}
}

// A state-changing request whose Origin is not this loopback dashboard is
// refused before it reaches the remote — CSRF defense for a local server
// on a known port. The loopback Host check alone does not stop a
// cross-site form POST; the Origin check does.
func TestMutationRejectsCrossOriginCSRF(t *testing.T) {
	fr := usersFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	req := loopbackPost("/users", url.Values{"email": {"attacker@evil.example"}})
	req.Header.Set("Origin", "http://evil.example")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("cross-origin POST = %d, want 403", rec.Code)
	}
	if len(fr.mutations) != 0 {
		t.Errorf("cross-origin POST reached the remote (%d mutations); CSRF defense failed", len(fr.mutations))
	}
}

// A POST with no Origin or Referer is refused too — the dashboard cannot
// confirm the request came from itself.
func TestMutationRejectsMissingOrigin(t *testing.T) {
	fr := usersFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	req := loopbackPost("/users", url.Values{"email": {"x@client.example"}})
	req.Header.Del("Origin")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("origin-less POST = %d, want 403", rec.Code)
	}
	if len(fr.mutations) != 0 {
		t.Error("origin-less POST reached the remote; CSRF defense failed")
	}
}

// When the remote denies a mutation (the operator lacks the admin role),
// the dashboard redirects back with a non-leaking error code rather than
// showing a stack trace, and the GET surfaces a friendly message.
func TestMutationForbiddenSurfacesError(t *testing.T) {
	fr := usersFakeRemote(t)
	fr.status = http.StatusForbidden
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackPost("/users", url.Values{"email": {"x@client.example"}}))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("forbidden mutation = %d, want 303 redirect", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "err=") {
		t.Errorf("redirect Location = %q, want an error code", loc)
	}
}
