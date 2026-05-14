package cedar

import (
	"fmt"
	"slices"
	"strings"

	"github.com/bensyverson/kura/internal/pii"
	cedarengine "github.com/cedar-policy/cedar-go"
)

// Compile renders the IR as Cedar policy text and guarantees the result
// is valid: it round-trips the generated text through the Cedar engine's
// parser and returns an error if the engine does not accept it, so a bug
// in the generator can never ship as a malformed policy.
//
// Each grant becomes a permit. Action-level access is one permit per
// (role, action, entity). PII visibility is a separate "viewPII" action:
// for every (role, entity, category) a read or list grant makes visible,
// one permit gated on context.category. A category with no such permit
// is denied at evaluation time and therefore masked.
func (p *Policy) Compile() (string, error) {
	var b strings.Builder

	for _, g := range p.Grants {
		fmt.Fprintf(&b, "permit (\n  principal in Role::%q,\n  action == Action::%q,\n  resource is %s\n);\n\n",
			g.Role, string(g.Action), g.Entity)
	}

	for _, v := range visibilityGrants(p) {
		fmt.Fprintf(&b, "permit (\n  principal in Role::%q,\n  action == Action::\"viewPII\",\n  resource is %s\n)\nwhen { context.category == %q };\n\n",
			v.role, v.entity, string(v.category))
	}

	text := b.String()
	if _, err := cedarengine.NewPolicySetFromBytes("kura", []byte(text)); err != nil {
		return "", fmt.Errorf("cedar: compiler produced invalid policy text: %w", err)
	}
	return text, nil
}

// visibility is one (role, entity, category) tuple a read/list grant
// makes visible.
type visibility struct {
	role     string
	entity   string
	category pii.Category
}

// visibilityGrants collects the deduplicated, stably ordered set of
// (role, entity, category) tuples across all read and list grants.
func visibilityGrants(p *Policy) []visibility {
	seen := make(map[visibility]bool)
	var out []visibility
	for _, g := range p.Grants {
		if !g.Action.isRead() {
			continue
		}
		for _, c := range g.VisiblePII {
			v := visibility{role: g.Role, entity: g.Entity, category: c}
			if !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	slices.SortFunc(out, func(a, b visibility) int {
		if a.role != b.role {
			return strings.Compare(a.role, b.role)
		}
		if a.entity != b.entity {
			return strings.Compare(a.entity, b.entity)
		}
		return strings.Compare(string(a.category), string(b.category))
	})
	return out
}
