package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/cedar"
	"github.com/bensyverson/kura/internal/data"
	"github.com/bensyverson/kura/internal/gate"
	"github.com/bensyverson/kura/internal/identity"
	"github.com/bensyverson/kura/internal/manifest"
	"github.com/bensyverson/kura/internal/pii"
)

// adminServer builds a server whose gate, user store, and IdP directory
// are wired consistently: the same MemUserStore both backs the gate's
// role resolution and is the Config.Users management surface, so a role
// granted through an endpoint is a role the gate enforces. It returns
// the server, the user store (so a test can inspect it), the IdP fake,
// and tokens for an admin, an auditor, and a plain user.
func adminServer(t *testing.T) (srv *Server, users *data.MemUserStore, idp *identity.FakeIdPDirectory, adminTok, auditorTok, userTok string) {
	t.Helper()
	m := &manifest.Manifest{
		Version: "1",
		Entities: []manifest.Entity{{Name: "patient", Fields: []manifest.Field{
			{Name: "full_name", Type: manifest.FieldString, PII: new(pii.CategoryPerson)},
		}}},
	}
	evaluator, err := cedar.NewEvaluator(cedar.DefaultPolicy(m))
	if err != nil {
		t.Fatalf("building evaluator: %v", err)
	}
	auth := identity.NewAuthenticator([]byte("test-signing-secret"))
	users = data.NewMemUserStore()
	for email, role := range map[string]string{
		"admin@client.com":   "admin",
		"auditor@client.com": "auditor",
		"user@client.com":    "user",
	} {
		if err := users.AddUser(t.Context(), email); err != nil {
			t.Fatalf("seeding user %s: %v", email, err)
		}
		if err := users.AssignRoles(t.Context(), email, role); err != nil {
			t.Fatalf("seeding role for %s: %v", email, err)
		}
	}
	idp = identity.NewFakeIdPDirectory()

	g, err := gate.New(auth, evaluator, users, m, pii.NewScanner(pii.NewFakeDetector()), audit.NewRecorder(audit.NewMemStore()))
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}

	cfg, _ := testConfig(t, "127.0.0.1:0")
	cfg.Auth = auth
	cfg.Gate = g
	cfg.Users = users
	cfg.IdP = idp
	srv, err = New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	mint := func(email string, typ identity.PrincipalType) string {
		tok, err := auth.Issue(identity.Principal{Type: typ, ID: email, Email: email, Domain: "client.com"}, time.Hour)
		if err != nil {
			t.Fatalf("issuing token for %s: %v", email, err)
		}
		return tok
	}
	return srv, users, idp,
		mint("admin@client.com", identity.PrincipalAdmin),
		mint("auditor@client.com", identity.PrincipalUser),
		mint("user@client.com", identity.PrincipalUser)
}

func doReq(t *testing.T, srv *Server, method, path, token, body string) *recorder {
	t.Helper()
	var r *http.Request
	if body != "" {
		r, _ = http.NewRequest(method, path, strings.NewReader(body))
	} else {
		r, _ = http.NewRequest(method, path, nil)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	rec := newRecorder()
	srv.Handler().ServeHTTP(rec, r)
	return rec
}

// dB5: a user can be added to the authorized list — but only by an
// admin. A plain user is forbidden; the auditor, who may review but not
// manage, is forbidden too.
func TestAddUserRequiresAdmin(t *testing.T) {
	srv, users, _, adminTok, auditorTok, userTok := adminServer(t)

	if rec := doReq(t, srv, http.MethodPost, "/api/users", userTok, `{"email":"new@client.com"}`); rec.status != http.StatusForbidden {
		t.Errorf("add user as plain user: status = %d, want 403", rec.status)
	}
	if rec := doReq(t, srv, http.MethodPost, "/api/users", auditorTok, `{"email":"new@client.com"}`); rec.status != http.StatusForbidden {
		t.Errorf("add user as auditor: status = %d, want 403", rec.status)
	}

	rec := doReq(t, srv, http.MethodPost, "/api/users", adminTok, `{"email":"new@client.com"}`)
	if rec.status != http.StatusNoContent {
		t.Fatalf("add user as admin: status = %d, want 204; body %s", rec.status, rec.body.String())
	}
	listed, err := users.ListUsers(t.Context())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	found := false
	for _, u := range listed {
		if u.Email == "new@client.com" {
			found = true
		}
	}
	if !found {
		t.Error("the added user is not on the authorized list")
	}
}

// dB5: listing the authorized users is review work — the read-only
// auditor may do it, an unauthenticated caller may not.
func TestListUsersAllowedForAuditorNotAnonymous(t *testing.T) {
	srv, _, _, _, auditorTok, _ := adminServer(t)

	if rec := doReq(t, srv, http.MethodGet, "/api/users", "", ""); rec.status != http.StatusUnauthorized {
		t.Errorf("list users unauthenticated: status = %d, want 401", rec.status)
	}

	rec := doReq(t, srv, http.MethodGet, "/api/users", auditorTok, "")
	if rec.status != http.StatusOK {
		t.Fatalf("list users as auditor: status = %d, want 200; body %s", rec.status, rec.body.String())
	}
	var resp struct {
		Users []data.User `json:"users"`
	}
	if err := json.Unmarshal(rec.body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding users body: %v", err)
	}
	if len(resp.Users) != 3 {
		t.Errorf("listed %d users, want the 3 seeded", len(resp.Users))
	}
}

// dB5: role assignment and revocation are variadic and atomic, and an
// admin endpoint drives them.
func TestAssignAndRevokeRolesVariadic(t *testing.T) {
	srv, users, _, adminTok, _, _ := adminServer(t)
	if err := users.AddUser(t.Context(), "new@client.com"); err != nil {
		t.Fatalf("seeding new user: %v", err)
	}

	rec := doReq(t, srv, http.MethodPost, "/api/users/new@client.com/roles", adminTok, `{"roles":["user","auditor"]}`)
	if rec.status != http.StatusOK && rec.status != http.StatusNoContent {
		t.Fatalf("assign roles: status = %d, want 200/204; body %s", rec.status, rec.body.String())
	}
	roles, _ := users.Roles(t.Context(), identity.Principal{Type: identity.PrincipalUser, ID: "new@client.com", Email: "new@client.com", Domain: "client.com"})
	if len(roles) != 2 {
		t.Errorf("after assign, roles = %v, want 2", roles)
	}

	rec = doReq(t, srv, http.MethodDelete, "/api/users/new@client.com/roles", adminTok, `{"roles":["user"]}`)
	if rec.status != http.StatusOK && rec.status != http.StatusNoContent {
		t.Fatalf("revoke roles: status = %d, want 200/204", rec.status)
	}
	roles, _ = users.Roles(t.Context(), identity.Principal{Type: identity.PrincipalUser, ID: "new@client.com", Email: "new@client.com", Domain: "client.com"})
	if len(roles) != 1 || roles[0] != "auditor" {
		t.Errorf("after revoke, roles = %v, want [auditor]", roles)
	}
}

// Assigning a role to a user not on the authorized list is a 404 — the
// two operations (add to list, grant role) are distinct.
func TestAssignRolesUnknownUserIsNotFound(t *testing.T) {
	srv, _, _, adminTok, _, _ := adminServer(t)
	rec := doReq(t, srv, http.MethodPost, "/api/users/ghost@client.com/roles", adminTok, `{"roles":["user"]}`)
	if rec.status != http.StatusNotFound {
		t.Errorf("assign roles to unlisted user: status = %d, want 404", rec.status)
	}
}

// vEr: the effective policy is readable through the API.
func TestEffectivePolicyIsReadable(t *testing.T) {
	srv, _, _, adminTok, _, _ := adminServer(t)
	rec := doReq(t, srv, http.MethodGet, "/api/policy", adminTok, "")
	if rec.status != http.StatusOK {
		t.Fatalf("read policy: status = %d, want 200; body %s", rec.status, rec.body.String())
	}
	var policy struct {
		Roles []struct {
			Name string `json:"name"`
		} `json:"roles"`
		Grants []struct {
			Role   string `json:"role"`
			Entity string `json:"entity"`
			Action string `json:"action"`
		} `json:"grants"`
	}
	if err := json.Unmarshal(rec.body.Bytes(), &policy); err != nil {
		t.Fatalf("decoding policy body %q: %v", rec.body.String(), err)
	}
	if len(policy.Roles) == 0 || len(policy.Grants) == 0 {
		t.Errorf("effective policy renders no roles/grants: %+v", policy)
	}
}

// vEr: policy authoring is not a server endpoint — there is no write
// method on /api/policy.
func TestPolicyHasNoWriteEndpoint(t *testing.T) {
	srv, _, _, adminTok, _, _ := adminServer(t)
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		rec := doReq(t, srv, method, "/api/policy", adminTok, `{"roles":[]}`)
		if rec.status == http.StatusOK {
			t.Errorf("%s /api/policy succeeded — policy authoring must not be a server endpoint", method)
		}
	}
}

// 9fd: an IdP mismatch — a suspended Google account still holding a Kura
// role — is detectable through the API.
func TestIdPMismatchesAreDetectable(t *testing.T) {
	srv, _, idp, adminTok, _, _ := adminServer(t)
	// admin@client.com holds a role; mark its Workspace account suspended.
	idp.Set("admin@client.com", identity.AccountSuspended)
	idp.Set("auditor@client.com", identity.AccountActive)
	idp.Set("user@client.com", identity.AccountActive)

	rec := doReq(t, srv, http.MethodGet, "/api/users/mismatches", adminTok, "")
	if rec.status != http.StatusOK {
		t.Fatalf("read mismatches: status = %d, want 200; body %s", rec.status, rec.body.String())
	}
	var resp struct {
		Mismatches []struct {
			Email  string `json:"email"`
			Status string `json:"status"`
		} `json:"mismatches"`
	}
	if err := json.Unmarshal(rec.body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding mismatches body: %v", err)
	}
	if len(resp.Mismatches) != 1 || resp.Mismatches[0].Email != "admin@client.com" {
		t.Fatalf("mismatches = %+v, want just admin@client.com", resp.Mismatches)
	}
	if resp.Mismatches[0].Status != string(identity.AccountSuspended) {
		t.Errorf("mismatch status = %q, want suspended", resp.Mismatches[0].Status)
	}
}

// Every admin route is a gated route — it goes through Gate.Admin, so it
// is authorized and audited by construction, exactly like the data
// routes.
func TestAdminRoutesAreGated(t *testing.T) {
	srv, _, _, _, _, _ := adminServer(t)
	for _, pattern := range []string{
		"POST /api/users", "GET /api/users",
		"POST /api/users/{email}/roles", "DELETE /api/users/{email}/roles",
		"GET /api/policy", "GET /api/users/mismatches",
	} {
		h, ok := srv.apiRoutes[pattern]
		if !ok {
			t.Errorf("admin route %q is not registered", pattern)
			continue
		}
		if _, gated := h.(gatedRoute); !gated {
			t.Errorf("admin route %q is %T, not a gatedRoute", pattern, h)
		}
	}
}
