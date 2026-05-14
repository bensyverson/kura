package cedar

import (
	"fmt"

	"github.com/bensyverson/kura/internal/identity"
	"github.com/bensyverson/kura/internal/pii"
	cedarengine "github.com/cedar-policy/cedar-go"
)

// Evaluator decides authorization requests against a compiled policy. It
// wraps the Cedar engine — Kura never re-implements Cedar evaluation.
type Evaluator struct {
	policies *cedarengine.PolicySet
	policy   *Policy // the IR this was compiled from, kept for rendering
}

// NewEvaluator compiles the IR and loads it into the Cedar engine. The
// policy should already have been validated against its manifest with
// Policy.ValidateAgainst.
func NewEvaluator(p *Policy) (*Evaluator, error) {
	text, err := p.Compile()
	if err != nil {
		return nil, err
	}
	ps, err := cedarengine.NewPolicySetFromBytes("kura-policy", []byte(text))
	if err != nil {
		return nil, fmt.Errorf("cedar: load policy set: %w", err)
	}
	return &Evaluator{policies: ps, policy: p}, nil
}

// Policy returns the IR the evaluator was compiled from. The effective
// policy is read-only here — authoring stays a repo/PR activity — so an
// adapter that surfaces "what may each role do" renders this rather than
// re-deriving it.
func (e *Evaluator) Policy() *Policy { return e.policy }

// Request is a single authorization question: may this principal, in
// these roles, perform this action on this resource — and of the PII
// categories detected in the resource, which may they see?
//
// DetectedPII carries the PII *categories* present in the resource. The
// evaluator decides visibility per category; it never sees, and never
// decides on, a column or field name.
type Request struct {
	Principal   identity.Principal
	Roles       []string
	Action      Action
	Entity      string
	ResourceID  string
	DetectedPII []pii.Category
}

// Decision is the outcome: whether the action is allowed, and for read
// and list actions, which detected PII categories are visible in
// plaintext and which must be masked.
type Decision struct {
	Allowed           bool
	VisibleCategories []pii.Category
	MaskedCategories  []pii.Category
}

// Decide answers the request. A denied action yields a Decision with no
// visible categories — if you cannot perform the action, there is
// nothing to see.
func (e *Evaluator) Decide(req Request) (Decision, error) {
	principalType := req.Principal.Type.CedarEntityType()
	if principalType == "" {
		return Decision{}, fmt.Errorf("cedar: principal %q has no Cedar entity type", req.Principal.Type)
	}

	entities := cedarengine.EntityMap{}
	var roleUIDs []cedarengine.EntityUID
	for _, r := range req.Roles {
		uid := cedarengine.NewEntityUID("Role", cedarengine.String(r))
		roleUIDs = append(roleUIDs, uid)
		entities[uid] = cedarengine.Entity{UID: uid}
	}

	principalUID := cedarengine.NewEntityUID(cedarengine.EntityType(principalType), cedarengine.String(req.Principal.ID))
	entities[principalUID] = cedarengine.Entity{UID: principalUID, Parents: cedarengine.NewEntityUIDSet(roleUIDs...)}

	resourceUID := cedarengine.NewEntityUID(cedarengine.EntityType(req.Entity), cedarengine.String(req.ResourceID))
	entities[resourceUID] = cedarengine.Entity{UID: resourceUID}

	allow := func(action string, ctx cedarengine.Record) bool {
		decision, _ := cedarengine.Authorize(e.policies, entities, cedarengine.Request{
			Principal: principalUID,
			Action:    cedarengine.NewEntityUID("Action", cedarengine.String(action)),
			Resource:  resourceUID,
			Context:   ctx,
		})
		return decision == cedarengine.Allow
	}

	d := Decision{Allowed: allow(string(req.Action), cedarengine.NewRecord(cedarengine.RecordMap{}))}
	if !d.Allowed || !req.Action.isRead() {
		return d, nil
	}

	for _, c := range req.DetectedPII {
		ctx := cedarengine.NewRecord(cedarengine.RecordMap{"category": cedarengine.String(string(c))})
		if allow("viewPII", ctx) {
			d.VisibleCategories = append(d.VisibleCategories, c)
		} else {
			d.MaskedCategories = append(d.MaskedCategories, c)
		}
	}
	return d, nil
}
