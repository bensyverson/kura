package dashboard

import (
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/bensyverson/kura/internal/cedar"
)

// policyView is the view-model the Cedar structured viewer renders: the
// policy IR projected for human reading — a per-entity grid of roles ×
// actions (with the PII each role sees), plus plain-language statements.
// It is read-only by construction; there is no editor field because
// authoring stays a repo/PR activity.
type policyView struct {
	Actions    []string
	Roles      []cedar.Role
	Entities   []policyEntity
	Statements []string
}

// policyEntity is one entity's slice of the grid: each defined role and
// what it may do to that entity.
type policyEntity struct {
	Entity string
	Rows   []policyRow
}

// policyRow is one role's row in an entity grid: a cell per action (in
// Actions order) and the PII categories the role sees in plaintext on a
// read or list.
type policyRow struct {
	Role       string
	Cells      []policyCell
	VisiblePII []string
}

// policyCell is one role × action square in an entity grid. It carries
// three states, not two: Granted (allowed), neither (grantable but not
// granted), and Unavailable (structurally impossible — an update or delete
// on an append-only entity, which the policy can never grant). Unavailable
// renders as N/A so a reviewer reads the immutability rather than mistaking
// it for a permission someone forgot to grant.
type policyCell struct {
	Granted     bool
	Unavailable bool
}

// handlePolicy renders the Cedar structured viewer: it reads the policy IR
// from the remote API and renders it server-side as a grid plus prose. An
// auth problem lands on sign-in; an unreachable remote on the error page.
func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	principal, err := s.api.whoami(r.Context())
	if err != nil {
		s.renderAuthOrError(w, "/policy", err)
		return
	}
	policy, err := s.api.policy(r.Context())
	if err != nil {
		s.renderAuthOrError(w, "/policy", err)
		return
	}
	m, err := s.api.manifest(r.Context())
	if err != nil {
		s.renderAuthOrError(w, "/policy", err)
		return
	}
	appendOnly := make(map[string]bool)
	for _, e := range m.Entities {
		if e.AppendOnly {
			appendOnly[e.Name] = true
		}
	}
	view := buildPolicyView(policy, appendOnly)
	s.render(w, http.StatusOK, "policy", pageData{
		Title:     "Policy",
		Nav:       navFor("/policy"),
		Principal: &principal,
		Policy:    &view,
	})
}

// buildPolicyView projects the IR into the viewer's grid and prose. It
// makes no policy decision — it reads the grants the policy already
// defines and arranges them for display: a cell per role × entity ×
// action, the visible-PII union for reads/lists, and one plain-language
// statement per role-with-access on each entity.
func buildPolicyView(p *cedar.Policy, appendOnly map[string]bool) policyView {
	actions := cedar.AllActions()
	actionLabels := make([]string, len(actions))
	for i, a := range actions {
		actionLabels[i] = string(a)
	}

	// Index grants by role|entity|action, and collect the entity set.
	type key struct{ role, entity string }
	granted := make(map[string]bool)
	piiByRoleEntity := make(map[key][]string)
	entitySet := make(map[string]bool)
	for _, g := range p.Grants {
		entitySet[g.Entity] = true
		granted[g.Role+"|"+g.Entity+"|"+string(g.Action)] = true
		if g.Action == cedar.ActionRead || g.Action == cedar.ActionList {
			k := key{g.Role, g.Entity}
			for _, c := range g.VisiblePII {
				if name := string(c); !slices.Contains(piiByRoleEntity[k], name) {
					piiByRoleEntity[k] = append(piiByRoleEntity[k], name)
				}
			}
		}
	}
	entities := make([]string, 0, len(entitySet))
	for e := range entitySet {
		entities = append(entities, e)
	}
	slices.Sort(entities)

	view := policyView{Actions: actionLabels, Roles: p.Roles}
	for _, entity := range entities {
		grid := policyEntity{Entity: entity}
		for _, role := range p.Roles {
			cells := make([]policyCell, len(actions))
			var allowed []string
			for i, a := range actions {
				if appendOnly[entity] && a.IsMutation() {
					cells[i] = policyCell{Unavailable: true}
					continue
				}
				if granted[role.Name+"|"+entity+"|"+string(a)] {
					cells[i] = policyCell{Granted: true}
					allowed = append(allowed, string(a))
				}
			}
			pii := piiByRoleEntity[key{role.Name, entity}]
			slices.Sort(pii)
			grid.Rows = append(grid.Rows, policyRow{Role: role.Name, Cells: cells, VisiblePII: pii})
			if len(allowed) > 0 {
				view.Statements = append(view.Statements, policyStatement(role.Name, entity, allowed, pii))
			}
		}
		view.Entities = append(view.Entities, grid)
	}
	return view
}

// policyStatement renders one grant cluster in plain language, e.g.
// "admin can read, delete patient; reads reveal private_person." When no
// PII is visible it says so, so a reviewer never has to infer masking from
// an absence.
func policyStatement(role, entity string, actions, visiblePII []string) string {
	stmt := fmt.Sprintf("%s can %s %s", role, strings.Join(actions, ", "), entity)
	readable := slices.Contains(actions, string(cedar.ActionRead)) || slices.Contains(actions, string(cedar.ActionList))
	if !readable {
		return stmt + "."
	}
	if len(visiblePII) == 0 {
		return stmt + "; all PII stays masked."
	}
	return stmt + "; reads reveal " + strings.Join(visiblePII, ", ") + "."
}
