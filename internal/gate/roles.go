package gate

import (
	"context"
	"sync"

	"github.com/bensyverson/kura/internal/identity"
)

// RoleResolver resolves a principal to the role names the authorization
// evaluator reasons about. It is a seam, not a policy: the gate asks it
// "which roles does this principal hold", and the Cedar policy decides
// what those roles may do. A principal with no roles is not an error —
// it is a principal that will be denied everything.
type RoleResolver interface {
	Roles(ctx context.Context, p identity.Principal) ([]string, error)
}

// MapRoleResolver is an in-memory RoleResolver keyed by principal ID. It
// backs tests today and the simplest real deployments; a database-backed
// resolver is a later, separate concern that satisfies the same
// interface.
type MapRoleResolver struct {
	mu          sync.Mutex
	byPrincipal map[string][]string
}

// NewMapRoleResolver returns an empty MapRoleResolver.
func NewMapRoleResolver() *MapRoleResolver {
	return &MapRoleResolver{byPrincipal: make(map[string][]string)}
}

// Assign sets the roles held by the principal with the given ID,
// replacing any previous assignment.
func (r *MapRoleResolver) Assign(principalID string, roles ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byPrincipal[principalID] = append([]string(nil), roles...)
}

// Roles returns the roles assigned to p, or an empty slice if none.
func (r *MapRoleResolver) Roles(_ context.Context, p identity.Principal) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.byPrincipal[p.ID]...), nil
}
