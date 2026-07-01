package gate

import (
	"context"
	"fmt"
	"slices"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/cedar"
	"github.com/bensyverson/kura/internal/identity"
)

// Role names the gate treats as carrying administrative capability.
// They match the names in cedar.DefaultPolicy's three-role model; a
// deployment that renames these roles loses the matching admin
// capability, which fails closed — the admin endpoints become
// unreachable rather than silently open.
const (
	roleAdmin   = "admin"
	roleAuditor = "auditor"
)

// AdminAction is an administrative operation. Unlike a data Action it
// touches no manifest entity and no PII — so the admin chain has no
// access-the-data or mask step, only authenticate, authorize, and audit.
type AdminAction string

const (
	// AdminManage mutates the authorized-user list or role assignments.
	// It is the admin role's capability alone.
	AdminManage AdminAction = "manage"
	// AdminReview reads effective policy and surfaces IdP mismatches —
	// access-review work, so the read-only auditor may do it too.
	AdminReview AdminAction = "review"
	// AdminErase crypto-shreds records — the right-to-be-forgotten
	// operation. Like AdminManage it is the admin role's capability alone:
	// the read-only auditor may review but never forget. It is a distinct
	// action so erasure is authorized and audited under its own name,
	// never conflated with ordinary record management.
	AdminErase AdminAction = "erase"
)

// AdminRequest is one administrative request through the gate. Resource
// names what the operation concerns, purely for the audit trail — the
// gate does not interpret it.
type AdminRequest struct {
	Token    string
	Action   AdminAction
	Resource audit.Resource
}

// Policy returns the effective authorization policy the gate enforces.
// It is read-only: policy authoring stays a repo/PR activity, so an
// adapter surfaces this rather than offering a write path.
func (g *Gate) Policy() *cedar.Policy { return g.evaluator.Policy() }

// Admin runs the gate chain for an administrative operation:
//
//	authenticate -> authorize -> do -> audit
//
// It is the admin-shaped sibling of Access and List. There is no data
// step — an admin op touches no manifest entity and no PII — so the
// caller-supplied do callback *is* the operation, and the gate owns when
// it runs (only after authorization passes) and that it is audited once
// it has. A denied request never reaches do; an operation whose access
// cannot be audited fails closed.
func (g *Gate) Admin(ctx context.Context, req AdminRequest, do func(context.Context) error) (identity.Principal, error) {
	principal, err := g.authenticate(ctx, req.Token)
	if err != nil {
		return identity.Principal{}, err
	}

	roles, err := g.roles.Roles(ctx, principal)
	if err != nil {
		return identity.Principal{}, fmt.Errorf("gate: resolving roles: %w", err)
	}
	allowed := adminActionAllows(req.Action, roles)

	outcome := audit.OutcomeAllowed
	if !allowed {
		outcome = audit.OutcomeDenied
	}
	if err := g.recorder.RecordAuthorization(ctx, principal, string(req.Action), req.Resource, outcome); err != nil {
		return identity.Principal{}, fmt.Errorf("gate: recording admin authorization: %w", err)
	}
	if !allowed {
		return identity.Principal{}, ErrDenied
	}

	if err := do(ctx); err != nil {
		return identity.Principal{}, fmt.Errorf("gate: admin operation: %w", err)
	}

	if err := g.recorder.RecordAccess(ctx, principal, string(req.Action), req.Resource); err != nil {
		return identity.Principal{}, fmt.Errorf("gate: recording admin access: %w", err)
	}
	return principal, nil
}

// adminActionAllows reports whether a principal holding roles may
// perform action. An unrecognized action is allowed by no role — fail
// closed.
func adminActionAllows(action AdminAction, roles []string) bool {
	switch action {
	case AdminManage, AdminErase:
		return slices.Contains(roles, roleAdmin)
	case AdminReview:
		return slices.Contains(roles, roleAdmin) || slices.Contains(roles, roleAuditor)
	default:
		return false
	}
}
