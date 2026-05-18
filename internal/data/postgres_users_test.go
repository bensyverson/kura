package data

import (
	"context"
	"errors"
	"slices"
	"testing"
)

func TestNewPostgresUserStoreRejectsMisconfiguration(t *testing.T) {
	if _, err := NewPostgresUserStore(nil, "tenant"); !errors.Is(err, ErrMissingDependency) {
		t.Errorf("nil db: err = %v, want ErrMissingDependency", err)
	}
}

func TestPostgresUserStoreIsAUserStore(t *testing.T) {
	var _ UserStore = (*PostgresUserStore)(nil)
}

// The authorized list round-trips: users added through the store are
// listed back, in a stable order, each with the roles assigned to them.
func TestPostgresUserStoreAddAssignAndList(t *testing.T) {
	env := newDataTestEnv(t)
	tenant := newTenantID(t, env)
	store, err := NewPostgresUserStore(connectAsAPIRole(t, env), tenant)
	if err != nil {
		t.Fatalf("NewPostgresUserStore: %v", err)
	}
	ctx := context.Background()

	for _, e := range []string{"bob@client.com", "alice@client.com"} {
		if err := store.AddUser(ctx, e); err != nil {
			t.Fatalf("AddUser(%q): %v", e, err)
		}
	}
	if err := store.AssignRoles(ctx, "alice@client.com", "admin", "auditor"); err != nil {
		t.Fatalf("AssignRoles: %v", err)
	}

	users, err := store.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("got %d users, want 2", len(users))
	}
	if users[0].Email != "alice@client.com" || users[1].Email != "bob@client.com" {
		t.Errorf("ListUsers order = %q, %q; want alice, bob", users[0].Email, users[1].Email)
	}
	gotRoles := append([]string(nil), users[0].Roles...)
	slices.Sort(gotRoles)
	if !slices.Equal(gotRoles, []string{"admin", "auditor"}) {
		t.Errorf("alice roles = %v, want [admin auditor]", gotRoles)
	}
	if len(users[1].Roles) != 0 {
		t.Errorf("bob roles = %v, want none", users[1].Roles)
	}
}

// AddUser is idempotent and AssignRoles / RevokeRoles are variadic,
// atomic, and idempotent — re-adding a user keeps their roles, and
// assigning an already-held role does not duplicate it.
func TestPostgresUserStoreMutationsAreIdempotent(t *testing.T) {
	env := newDataTestEnv(t)
	tenant := newTenantID(t, env)
	store, err := NewPostgresUserStore(connectAsAPIRole(t, env), tenant)
	if err != nil {
		t.Fatalf("NewPostgresUserStore: %v", err)
	}
	ctx := context.Background()

	if err := store.AddUser(ctx, "bob@client.com"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if err := store.AssignRoles(ctx, "bob@client.com", "user", "auditor"); err != nil {
		t.Fatalf("AssignRoles: %v", err)
	}
	// Re-add must not disturb existing roles.
	if err := store.AddUser(ctx, "bob@client.com"); err != nil {
		t.Fatalf("re-AddUser: %v", err)
	}
	// Overlapping assign must not duplicate.
	if err := store.AssignRoles(ctx, "bob@client.com", "auditor", "admin"); err != nil {
		t.Fatalf("AssignRoles (overlapping): %v", err)
	}
	roles, err := store.Roles(ctx, human("bob@client.com"))
	if err != nil {
		t.Fatalf("Roles: %v", err)
	}
	slices.Sort(roles)
	if !slices.Equal(roles, []string{"admin", "auditor", "user"}) {
		t.Errorf("roles = %v, want [admin auditor user] with no duplicates", roles)
	}

	// Revoke is variadic; a role not held is a no-op.
	if err := store.RevokeRoles(ctx, "bob@client.com", "admin", "user", "never-held"); err != nil {
		t.Fatalf("RevokeRoles: %v", err)
	}
	roles, _ = store.Roles(ctx, human("bob@client.com"))
	if !slices.Equal(roles, []string{"auditor"}) {
		t.Errorf("roles after revoke = %v, want [auditor]", roles)
	}
}

// A role operation on a user not on the authorized list is
// ErrUserNotFound — and changes nothing.
func TestPostgresUserStoreRoleOpsRequireListedUser(t *testing.T) {
	env := newDataTestEnv(t)
	tenant := newTenantID(t, env)
	store, err := NewPostgresUserStore(connectAsAPIRole(t, env), tenant)
	if err != nil {
		t.Fatalf("NewPostgresUserStore: %v", err)
	}
	ctx := context.Background()

	if err := store.AssignRoles(ctx, "ghost@client.com", "admin"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("AssignRoles(unlisted) = %v, want ErrUserNotFound", err)
	}
	if err := store.RevokeRoles(ctx, "ghost@client.com", "admin"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("RevokeRoles(unlisted) = %v, want ErrUserNotFound", err)
	}
}

// DeactivateUser strips every role atomically and leaves the user on the
// list — `kura user deactivate` is auditable history, not a delete.
func TestPostgresUserStoreDeactivate(t *testing.T) {
	env := newDataTestEnv(t)
	tenant := newTenantID(t, env)
	store, err := NewPostgresUserStore(connectAsAPIRole(t, env), tenant)
	if err != nil {
		t.Fatalf("NewPostgresUserStore: %v", err)
	}
	ctx := context.Background()
	if err := store.AddUser(ctx, "bob@client.com"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if err := store.AssignRoles(ctx, "bob@client.com", "user", "auditor", "admin"); err != nil {
		t.Fatalf("AssignRoles: %v", err)
	}

	if err := store.DeactivateUser(ctx, "bob@client.com"); err != nil {
		t.Fatalf("DeactivateUser: %v", err)
	}
	roles, _ := store.Roles(ctx, human("bob@client.com"))
	if len(roles) != 0 {
		t.Errorf("roles after deactivate = %v, want none", roles)
	}
	users, _ := store.ListUsers(ctx)
	if len(users) != 1 || users[0].Email != "bob@client.com" {
		t.Errorf("deactivated user is no longer on the authorized list: %+v", users)
	}

	// Idempotent.
	if err := store.DeactivateUser(ctx, "bob@client.com"); err != nil {
		t.Errorf("repeat DeactivateUser: %v", err)
	}
	// Unlisted user is ErrUserNotFound — same as the role ops.
	if err := store.DeactivateUser(ctx, "ghost@client.com"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("DeactivateUser(unlisted) = %v, want ErrUserNotFound", err)
	}
}

// frQ-style isolation: the authorized list is tenant-scoped by RLS. A
// store for one tenant cannot see — or mutate — another tenant's users.
func TestPostgresUserStoreCrossTenantIsolation(t *testing.T) {
	env := newDataTestEnv(t)
	tenantA := newTenantID(t, env)
	tenantB := newTenantID(t, env)
	apiPool := connectAsAPIRole(t, env)
	ctx := context.Background()

	storeA, err := NewPostgresUserStore(apiPool, tenantA)
	if err != nil {
		t.Fatalf("NewPostgresUserStore(A): %v", err)
	}
	storeB, err := NewPostgresUserStore(apiPool, tenantB)
	if err != nil {
		t.Fatalf("NewPostgresUserStore(B): %v", err)
	}

	if err := storeA.AddUser(ctx, "alice@client.com"); err != nil {
		t.Fatalf("AddUser under tenant A: %v", err)
	}
	if err := storeA.AssignRoles(ctx, "alice@client.com", "admin"); err != nil {
		t.Fatalf("AssignRoles under tenant A: %v", err)
	}

	// Tenant B sees an empty list and resolves no roles for A's user.
	usersB, err := storeB.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers under tenant B: %v", err)
	}
	if len(usersB) != 0 {
		t.Errorf("tenant B sees %d users, want 0 — RLS should hide tenant A's list", len(usersB))
	}
	rolesB, err := storeB.Roles(ctx, human("alice@client.com"))
	if err != nil {
		t.Fatalf("Roles under tenant B: %v", err)
	}
	if len(rolesB) != 0 {
		t.Errorf("tenant B resolved roles %v for tenant A's user — RLS breach", rolesB)
	}
	// Tenant B cannot grant roles to A's user either — to B it is not on
	// the list at all.
	if err := storeB.AssignRoles(ctx, "alice@client.com", "auditor"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("cross-tenant AssignRoles = %v, want ErrUserNotFound", err)
	}

	// Tenant A still sees its own user intact.
	rolesA, err := storeA.Roles(ctx, human("alice@client.com"))
	if err != nil {
		t.Fatalf("Roles under tenant A: %v", err)
	}
	if !slices.Equal(rolesA, []string{"admin"}) {
		t.Errorf("tenant A roles = %v, want [admin]", rolesA)
	}
}
