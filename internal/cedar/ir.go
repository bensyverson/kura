// Package cedar is Kura's authorization core. It has three pieces:
//
//   - an intermediate representation (IR) of the policy space — roles ×
//     entities × PII-categories × actions — whose axes come from the
//     schema manifest;
//   - a compiler from the IR to Cedar policy text;
//   - an evaluation wrapper around the Cedar engine that decides each
//     request against principal, action, resource, and the resource's
//     detected PII categories.
//
// The IR is the constrained, safe subset of what Cedar can express. It
// is the same model the dashboard's structured viewer renders and the
// future structured editor will edit — built once, here. Free-form Cedar
// authoring stays a repo/PR activity, deliberately outside the IR.
package cedar

import (
	"fmt"

	"github.com/bensyverson/kura/internal/manifest"
	"github.com/bensyverson/kura/internal/pii"
)

// Action is an operation a role can be granted on an entity.
type Action string

const (
	ActionRead   Action = "read"
	ActionList   Action = "list"
	ActionCreate Action = "create"
	ActionUpdate Action = "update"
	ActionDelete Action = "delete"
)

// AllActions returns every recognized action, in a stable order.
func AllActions() []Action {
	return []Action{ActionRead, ActionList, ActionCreate, ActionUpdate, ActionDelete}
}

// Valid reports whether a is a recognized action.
func (a Action) Valid() bool {
	switch a {
	case ActionRead, ActionList, ActionCreate, ActionUpdate, ActionDelete:
		return true
	default:
		return false
	}
}

// isRead reports whether a is an action whose result is data a caller
// sees — and therefore an action to which PII visibility applies.
func (a Action) isRead() bool {
	return a == ActionRead || a == ActionList
}

// Role is a named bundle of permissions. Principals are assigned roles;
// grants attach permissions to roles. The JSON tags are deliberate: the
// IR is the model an adapter renders read-only (the HTTP API's policy
// endpoint, the dashboard's structured viewer).
type Role struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// Grant permits a Role to perform an Action on an Entity. For read and
// list actions, VisiblePII names the PII categories the role may see in
// plaintext — any category not listed is masked. VisiblePII must be
// empty for non-read actions.
type Grant struct {
	Role       string         `json:"role"`
	Entity     string         `json:"entity"`
	Action     Action         `json:"action"`
	VisiblePII []pii.Category `json:"visiblePII,omitempty"`
}

// Policy is the IR: the roles a deployment defines and the grants that
// give them permissions. It is permit-only — there is deny-by-default
// and no forbid rules, which is what keeps it the safe subset.
type Policy struct {
	Roles  []Role  `json:"roles"`
	Grants []Grant `json:"grants"`
}

// ValidateAgainst checks the policy is internally consistent and that
// every grant references a role it defines, an entity the manifest
// declares, a recognized action, and recognized PII categories. It
// reports the first problem it finds.
func (p *Policy) ValidateAgainst(m *manifest.Manifest) error {
	roles := make(map[string]bool, len(p.Roles))
	for _, r := range p.Roles {
		if r.Name == "" {
			return fmt.Errorf("cedar: role name must not be empty")
		}
		if roles[r.Name] {
			return fmt.Errorf("cedar: duplicate role %q", r.Name)
		}
		roles[r.Name] = true
	}
	for i, g := range p.Grants {
		if !roles[g.Role] {
			return fmt.Errorf("cedar: grant #%d references unknown role %q", i+1, g.Role)
		}
		if _, ok := m.Entity(g.Entity); !ok {
			return fmt.Errorf("cedar: grant #%d references entity %q absent from the manifest", i+1, g.Entity)
		}
		if !g.Action.Valid() {
			return fmt.Errorf("cedar: grant #%d has invalid action %q", i+1, g.Action)
		}
		if len(g.VisiblePII) > 0 && !g.Action.isRead() {
			return fmt.Errorf("cedar: grant #%d sets VisiblePII on non-read action %q", i+1, g.Action)
		}
		for _, c := range g.VisiblePII {
			if !c.Valid() {
				return fmt.Errorf("cedar: grant #%d has unrecognized PII category %q", i+1, c)
			}
		}
	}
	return nil
}

// DefaultPolicy builds the default three-role model — admin, user,
// read-only auditor — over every entity in the manifest:
//
//   - admin: every action on every entity; reads see every PII category.
//   - user: every action on every entity; reads see every PII category
//     except the high-sensitivity ones, which stay masked.
//   - auditor: read and list only; no PII category is ever visible.
//
// It is a starting point a deployment edits, not a fixed policy.
func DefaultPolicy(m *manifest.Manifest) *Policy {
	p := &Policy{
		Roles: []Role{
			{Name: "admin", Description: "Full access to every entity, action, and PII category."},
			{Name: "user", Description: "Day-to-day access; high-sensitivity PII stays masked."},
			{Name: "auditor", Description: "Read-only access for access review; all PII masked."},
		},
	}

	allCats := pii.Categories()
	var userCats []pii.Category
	for _, c := range allCats {
		if !c.HighSensitivity() {
			userCats = append(userCats, c)
		}
	}

	for _, e := range m.Entities {
		for _, a := range AllActions() {
			admin := Grant{Role: "admin", Entity: e.Name, Action: a}
			user := Grant{Role: "user", Entity: e.Name, Action: a}
			if a.isRead() {
				admin.VisiblePII = append([]pii.Category(nil), allCats...)
				user.VisiblePII = append([]pii.Category(nil), userCats...)
			}
			p.Grants = append(p.Grants, admin, user)
		}
		for _, a := range []Action{ActionRead, ActionList} {
			p.Grants = append(p.Grants, Grant{Role: "auditor", Entity: e.Name, Action: a})
		}
	}
	return p
}
