package main

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// `kura role assign --role admin --role auditor alice bob` is variadic
// in both roles and users: two POST /api/users/{email}/roles calls,
// each carrying the full role set. Atomic at the data layer (one tx
// per user), idempotent (re-running grants nothing new).
func TestRoleAssignIsVariadicInRolesAndUsers(t *testing.T) {
	fake := newFakeAdminServer(t)
	fake.users["alice@client.com"] = nil
	fake.users["bob@client.com"] = nil
	server := setupCLITestAgainst(t, fake)

	stdout, _, err := runRoot(t,
		"role", "assign",
		"--role", "admin", "--role", "auditor",
		"alice@client.com", "bob@client.com",
		"--server", server)
	if err != nil {
		t.Fatalf("role assign: %v", err)
	}
	posts := fake.callsOf(http.MethodPost)
	if len(posts) != 2 {
		t.Fatalf("variadic role assign: got %d POST calls, want 2 (one per user)", len(posts))
	}
	for _, c := range posts {
		var b struct {
			Roles []string `json:"roles"`
		}
		if err := json.Unmarshal([]byte(c.body), &b); err != nil {
			t.Fatalf("decode body %q: %v", c.body, err)
		}
		slices.Sort(b.Roles)
		if !slices.Equal(b.Roles, []string{"admin", "auditor"}) {
			t.Errorf("call body roles = %v, want [admin auditor]", b.Roles)
		}
	}

	for _, email := range []string{"alice@client.com", "bob@client.com"} {
		got := append([]string(nil), fake.users[email]...)
		slices.Sort(got)
		if !slices.Equal(got, []string{"admin", "auditor"}) {
			t.Errorf("%s roles = %v, want [admin auditor]", email, got)
		}
	}
	if !strings.Contains(stdout.String(), "Granted") {
		t.Errorf("ack should name the action:\n%s", stdout.String())
	}

	// Idempotent: re-run; per-user role set still has just the two.
	if _, _, err := runRoot(t,
		"role", "assign",
		"--role", "admin", "--role", "auditor",
		"alice@client.com", "bob@client.com",
		"--server", server); err != nil {
		t.Fatalf("re-assign: %v", err)
	}
	for _, email := range []string{"alice@client.com", "bob@client.com"} {
		if len(fake.users[email]) != 2 {
			t.Errorf("after idempotent re-assign, %s roles = %v, want 2 unique", email, fake.users[email])
		}
	}
}

// `kura role revoke --role <r> <email>...` is the inverse — variadic,
// per-user atomic, idempotent. Revoking a role the user does not hold
// is a no-op (server-level), and the per-user revoke leaves any roles
// not named in place.
func TestRoleRevokeIsVariadic(t *testing.T) {
	fake := newFakeAdminServer(t)
	fake.users["alice@client.com"] = []string{"admin", "auditor", "user"}
	fake.users["bob@client.com"] = []string{"auditor", "user"}
	server := setupCLITestAgainst(t, fake)

	if _, _, err := runRoot(t,
		"role", "revoke",
		"--role", "auditor",
		"alice@client.com", "bob@client.com",
		"--server", server); err != nil {
		t.Fatalf("role revoke: %v", err)
	}
	if slices.Contains(fake.users["alice@client.com"], "auditor") || slices.Contains(fake.users["bob@client.com"], "auditor") {
		t.Errorf("auditor still present after revoke: alice=%v bob=%v",
			fake.users["alice@client.com"], fake.users["bob@client.com"])
	}
	if !slices.Contains(fake.users["alice@client.com"], "admin") {
		t.Error("revoke stripped roles it should not have")
	}
}

// `kura role assign` without --role is a usage error that names the
// missing flag — the agent gets the fix in the first line.
func TestRoleAssignRequiresAtLeastOneRole(t *testing.T) {
	fake := newFakeAdminServer(t)
	fake.users["alice@client.com"] = nil
	server := setupCLITestAgainst(t, fake)

	_, _, err := runRoot(t, "role", "assign", "alice@client.com", "--server", server)
	if err == nil {
		t.Fatal("expected a usage error")
	}
	if !strings.Contains(err.Error(), "--role") {
		t.Errorf("error %q does not name --role as the fix", err)
	}
}

// `kura role list` renders the effective policy — roles and the
// role→entity:action grants — read-only by design.
func TestRoleListRendersPolicy(t *testing.T) {
	fake := newFakeAdminServer(t)
	server := setupCLITestAgainst(t, fake)

	stdout, _, err := runRoot(t, "role", "list", "--server", server)
	if err != nil {
		t.Fatalf("role list: %v", err)
	}
	got := stdout.String()
	for _, want := range []string{"admin", "auditor", "patient", "read", "list"} {
		if !strings.Contains(got, want) {
			t.Errorf("policy view missing %q:\n%s", want, got)
		}
	}
}
