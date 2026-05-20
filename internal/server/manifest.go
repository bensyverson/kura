package server

import (
	"context"
	"net/http"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/gate"
	"github.com/bensyverson/kura/internal/identity"
)

// registerManifestRoute mounts GET /api/manifest. The schema manifest —
// entities, fields (with their PII categories), and relationships — drives
// the dashboard's data browser, the CLI query/show verbs, and the policy
// IR; the data browser needs it to render any entity with no
// entity-specific code. Like the overview and policy reads it runs through
// Gate.Admin as an AdminReview operation, so the schema is authorized
// against the caller's roles and audited by construction: the admin and the
// read-only auditor may see it, a plain user may not. It exposes the schema
// only — no record, no field value — so there is nothing here for the gate
// to mask.
func (s *Server) registerManifestRoute() {
	s.registerAdmin("GET /api/manifest", manifestBinding(s.cfg.Gate))
}

// manifestBinding builds the binding for GET /api/manifest: an AdminReview
// read that returns the gate's manifest verbatim. The manifest's own JSON
// tags are its wire contract (they are the on-disk schema format), so the
// adapter serializes it directly rather than projecting a separate shape.
func manifestBinding(g *gate.Gate) adminBinding {
	return func(r *http.Request, _ identity.Principal) (gate.AdminRequest, adminOp, error) {
		req := gate.AdminRequest{
			Token:    bearerToken(r),
			Action:   gate.AdminReview,
			Resource: audit.Resource{Entity: "manifest"},
		}
		op := func(_ context.Context) (any, error) {
			return g.Manifest(), nil
		}
		return req, op, nil
	}
}
