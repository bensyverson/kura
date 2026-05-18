package data

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/bensyverson/kura/internal/identity"
)

func human(email string) identity.Principal {
	return identity.Principal{Type: identity.PrincipalUser, ID: email, Email: email, Tenant: "client.com"}
}

func TestMemUserStoreAddAndList(t *testing.T) {
	s := NewMemUserStore()
	ctx := context.Background()
	for _, e := range []string{"bob@client.com", "alice@client.com"} {
		if err := s.AddUser(ctx, e); err != nil {
			t.Fatalf("AddUser(%q): %v", e, err)
		}
	}
	users, err := s.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("got %d users, want 2", len(users))
	}
	// Listed in a stable (sorted) order so the output is deterministic.
	if users[0].Email != "alice@client.com" || users[1].Email != "bob@client.com" {
		t.Errorf("ListUsers order = %q, %q; want alice, bob", users[0].Email, users[1].Email)
	}
	if len(users[0].Roles) != 0 {
		t.Errorf("a freshly added user has roles %v, want none", users[0].Roles)
	}
}

// Adding an already-listed user is a no-op, not an error, and does not
// disturb the roles they already hold.
func TestMemUserStoreAddIsIdempotent(t *testing.T) {
	s := NewMemUserStore()
	ctx := context.Background()
	_ = s.AddUser(ctx, "bob@client.com")
	_ = s.AssignRoles(ctx, "bob@client.com", "user")
	if err := s.AddUser(ctx, "bob@client.com"); err != nil {
		t.Fatalf("re-AddUser: %v", err)
	}
	users, _ := s.ListUsers(ctx)
	if len(users) != 1 {
		t.Fatalf("got %d users after re-add, want 1", len(users))
	}
	if !slices.Equal(users[0].Roles, []string{"user"}) {
		t.Errorf("re-add disturbed roles: %v, want [user]", users[0].Roles)
	}
}

// Role assignment is variadic and idempotent: assigning several roles at
// once, including one already held, leaves each role present exactly
// once.
func TestMemUserStoreAssignRolesVariadicAndIdempotent(t *testing.T) {
	s := NewMemUserStore()
	ctx := context.Background()
	_ = s.AddUser(ctx, "bob@client.com")

	if err := s.AssignRoles(ctx, "bob@client.com", "user", "auditor"); err != nil {
		t.Fatalf("AssignRoles: %v", err)
	}
	if err := s.AssignRoles(ctx, "bob@client.com", "auditor", "admin"); err != nil {
		t.Fatalf("AssignRoles (overlapping): %v", err)
	}
	roles, err := s.Roles(ctx, human("bob@client.com"))
	if err != nil {
		t.Fatalf("Roles: %v", err)
	}
	slices.Sort(roles)
	if !slices.Equal(roles, []string{"admin", "auditor", "user"}) {
		t.Errorf("roles = %v, want [admin auditor user] with no duplicates", roles)
	}
}

// Assigning or revoking roles for a user not on the authorized list is
// ErrUserNotFound — the two are distinct operations: a user is added to
// the list first, then granted roles.
func TestMemUserStoreRoleOpsRequireAListedUser(t *testing.T) {
	s := NewMemUserStore()
	ctx := context.Background()
	if err := s.AssignRoles(ctx, "ghost@client.com", "admin"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("AssignRoles(unlisted) = %v, want ErrUserNotFound", err)
	}
	if err := s.RevokeRoles(ctx, "ghost@client.com", "admin"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("RevokeRoles(unlisted) = %v, want ErrUserNotFound", err)
	}
}

// Revocation is variadic; revoking a role the user does not hold is a
// no-op, not an error.
func TestMemUserStoreRevokeRoles(t *testing.T) {
	s := NewMemUserStore()
	ctx := context.Background()
	_ = s.AddUser(ctx, "bob@client.com")
	_ = s.AssignRoles(ctx, "bob@client.com", "user", "auditor", "admin")

	if err := s.RevokeRoles(ctx, "bob@client.com", "admin", "user", "never-held"); err != nil {
		t.Fatalf("RevokeRoles: %v", err)
	}
	roles, _ := s.Roles(ctx, human("bob@client.com"))
	if !slices.Equal(roles, []string{"auditor"}) {
		t.Errorf("roles after revoke = %v, want [auditor]", roles)
	}
}

// Roles resolves a principal to its role names, satisfying
// gate.RoleResolver. A principal not on the authorized list has no roles
// — not an error, just no access.
func TestMemUserStoreRolesForUnlistedPrincipalIsEmpty(t *testing.T) {
	s := NewMemUserStore()
	roles, err := s.Roles(context.Background(), human("nobody@client.com"))
	if err != nil {
		t.Fatalf("Roles: %v", err)
	}
	if len(roles) != 0 {
		t.Errorf("Roles for an unlisted principal = %v, want empty", roles)
	}
}

func TestMemUserStoreIsAUserStore(t *testing.T) {
	var _ UserStore = NewMemUserStore()
}

// DetectIdPMismatches flags every authorized user who still holds roles
// but whose identity-provider account is no longer active — suspended
// or absent. A user with no roles is never a mismatch (there is no
// access to revoke), and an active account is never a mismatch.
func TestDetectIdPMismatches(t *testing.T) {
	ctx := context.Background()
	store := NewMemUserStore()
	for _, e := range []string{"active@client.com", "suspended@client.com", "absent@client.com", "noroles@client.com"} {
		if err := store.AddUser(ctx, e); err != nil {
			t.Fatalf("AddUser(%q): %v", e, err)
		}
	}
	_ = store.AssignRoles(ctx, "active@client.com", "user")
	_ = store.AssignRoles(ctx, "suspended@client.com", "admin")
	_ = store.AssignRoles(ctx, "absent@client.com", "auditor")
	// noroles@client.com is on the list but holds no roles.

	dir := identity.NewFakeIdPDirectory().
		Set("active@client.com", identity.AccountActive).
		Set("suspended@client.com", identity.AccountSuspended)
	// absent@client.com and noroles@client.com are unknown to the
	// directory — AccountAbsent.

	mismatches, err := DetectIdPMismatches(ctx, store, dir)
	if err != nil {
		t.Fatalf("DetectIdPMismatches: %v", err)
	}
	got := map[string]identity.AccountStatus{}
	for _, m := range mismatches {
		got[m.Email] = m.Status
	}
	if len(got) != 2 {
		t.Fatalf("got %d mismatches, want 2: %+v", len(got), mismatches)
	}
	if got["suspended@client.com"] != identity.AccountSuspended {
		t.Errorf("suspended user mismatch status = %q, want suspended", got["suspended@client.com"])
	}
	if got["absent@client.com"] != identity.AccountAbsent {
		t.Errorf("absent user mismatch status = %q, want absent", got["absent@client.com"])
	}
	if _, flagged := got["active@client.com"]; flagged {
		t.Error("an active account was flagged as a mismatch")
	}
	if _, flagged := got["noroles@client.com"]; flagged {
		t.Error("a roleless user was flagged as a mismatch — there is no access to revoke")
	}
}
