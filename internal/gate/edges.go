package gate

import (
	"context"
	"fmt"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/cedar"
	"github.com/bensyverson/kura/internal/identity"
)

// EdgeView is one relationship edge as returned through the gate: the
// relationship name, the two record ids it connects, and the source record's
// order key (its value from the shared record sequence). An edge carries no
// field values — only ids, a relationship name, and a sequence number — so
// there is nothing to mask; the gate authorizes and audits the read, then
// returns the edges verbatim. It is the gate's projection of a data.Edge.
type EdgeView struct {
	Relationship string
	SourceID     string
	SourceSeq    int64
	TargetID     string
}

// EdgesRequest is one request to read a record's relationship edges through
// the gate. ResourceID is the record whose edges are read; Entity is the
// entity it belongs to, which the read is authorized against.
type EdgesRequest struct {
	Token      string
	Entity     string
	ResourceID string
}

// EdgesFetcher reads a record's edges. Like a Fetcher it runs only after
// authorization passes — so it cannot be a way around the gate — and the
// gate returns whatever it produces, in the order it produces it (the store
// orders incoming edges by the source record's sequence).
type EdgesFetcher func(ctx context.Context) ([]EdgeView, error)

// EdgesResult is what a caller gets back from a successful Edges read: the
// resolved principal and the record's edges.
type EdgesResult struct {
	Principal identity.Principal
	Edges     []EdgeView
}

// Edges runs the enforcement chain for reading a record's relationship edges:
//
//	authenticate -> authorize(read) -> access -> audit
//
// It is the edge-shaped sibling of Access, with one difference: there is no
// masking step, because an edge is ids and a relationship name with no field
// values to redact. The read is authorized as ActionRead on the record whose
// edges are being read — if you may read the record, you may see how it is
// connected — and audited as one read access. A denied request never reaches
// the fetch; a request whose access cannot be audited fails closed.
func (g *Gate) Edges(ctx context.Context, req EdgesRequest, fetch EdgesFetcher) (EdgesResult, error) {
	principal, err := g.authenticate(ctx, req.Token)
	if err != nil {
		return EdgesResult{}, err
	}

	if _, err := g.authorize(ctx, principal, cedar.ActionRead, req.Entity, req.ResourceID); err != nil {
		return EdgesResult{}, err
	}

	edges, err := fetch(ctx)
	if err != nil {
		return EdgesResult{}, fmt.Errorf("gate: data access: %w", err)
	}

	if err := g.recorder.RecordAccess(ctx, principal, string(cedar.ActionRead), audit.Resource{Entity: req.Entity, ID: req.ResourceID}); err != nil {
		return EdgesResult{}, fmt.Errorf("gate: recording access: %w", err)
	}

	return EdgesResult{Principal: principal, Edges: edges}, nil
}
