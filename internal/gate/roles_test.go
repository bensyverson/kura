package gate

import (
	"context"
	"testing"

	"github.com/bensyverson/kura/internal/identity"
)

func TestMapRoleResolverReturnsAssignedRoles(t *testing.T) {
	r := NewMapRoleResolver()
	r.Assign("alice", "admin", "user")

	got, err := r.Roles(context.Background(), identity.Principal{Type: identity.PrincipalService, ID: "alice"})
	if err != nil {
		t.Fatalf("Roles: %v", err)
	}
	if len(got) != 2 || got[0] != "admin" || got[1] != "user" {
		t.Errorf("Roles = %v, want [admin user]", got)
	}
}

func TestMapRoleResolverReturnsNoRolesForAnUnknownPrincipal(t *testing.T) {
	r := NewMapRoleResolver()

	got, err := r.Roles(context.Background(), identity.Principal{Type: identity.PrincipalService, ID: "nobody"})
	if err != nil {
		t.Fatalf("Roles: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Roles for unknown principal = %v, want empty", got)
	}
}
