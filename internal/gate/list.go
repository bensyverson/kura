package gate

import (
	"context"
	"fmt"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/cedar"
	"github.com/bensyverson/kura/internal/identity"
)

// Page-size bounds for List. The gate is "bounded by default": a list
// request with no limit gets DefaultPageSize, and one asking for more
// than MaxPageSize is clamped to it — an adapter cannot dump an
// unbounded result set through the gate, no matter what it asks for.
const (
	DefaultPageSize = 50
	MaxPageSize     = 200
)

// ListRequest is one request to read a bounded page of an entity's
// records through the gate. Limit and Offset are advisory: the gate
// clamps Limit into [1, MaxPageSize] (with 0 meaning DefaultPageSize)
// and floors Offset at zero before any fetch runs.
type ListRequest struct {
	Token  string
	Entity string
	Limit  int
	Offset int
}

// Record is one record in a list result: its id and its field values.
// The fields are masked by the time a caller sees them, exactly as a
// single Access result is.
type Record struct {
	ID     string
	Fields map[string]string
}

// ListFetcher reads a bounded page of records. The gate invokes it only
// after authorization passes, and only with a limit and offset it has
// already clamped — so a ListFetcher cannot be a way around the gate's
// bounds any more than a Fetcher can be a way around its masking.
type ListFetcher func(ctx context.Context, limit, offset int) ([]Record, error)

// ListResult is what a caller gets back from a successful List: the
// resolved principal, the masked page of records, and the effective
// limit and offset the gate actually applied (which differ from the
// request when it was clamped).
type ListResult struct {
	Principal identity.Principal
	Records   []Record
	Limit     int
	Offset    int
}

// List runs the full enforcement chain for a list request:
//
//	authenticate -> authorize -> access -> mask -> audit
//
// It is the list-shaped sibling of Access: the same welded chain, but
// the authorization step asks the ActionList question, the fetch reads a
// bounded page, every record in the page is masked, and the whole page
// is one audit event — a list happened, on the entity, touching no
// single record id. A denied request never reaches the fetch; a request
// whose access cannot be audited fails closed.
func (g *Gate) List(ctx context.Context, req ListRequest, fetch ListFetcher) (ListResult, error) {
	principal, err := g.authenticate(ctx, req.Token)
	if err != nil {
		return ListResult{}, err
	}

	// A list touches no single record, so it authorizes against the
	// entity with an empty resource id.
	decision, err := g.authorize(ctx, principal, cedar.ActionList, req.Entity, "")
	if err != nil {
		return ListResult{}, err
	}

	limit, offset := boundPage(req.Limit, req.Offset)
	records, err := fetch(ctx, limit, offset)
	if err != nil {
		return ListResult{}, fmt.Errorf("gate: data access: %w", err)
	}

	for i := range records {
		masked, err := g.mask(ctx, records[i].Fields, decision)
		if err != nil {
			return ListResult{}, err
		}
		records[i].Fields = masked
	}

	if err := g.recorder.RecordAccess(ctx, principal, string(cedar.ActionList), audit.Resource{Entity: req.Entity}); err != nil {
		return ListResult{}, fmt.Errorf("gate: recording access: %w", err)
	}

	return ListResult{Principal: principal, Records: records, Limit: limit, Offset: offset}, nil
}

// boundPage clamps a requested page into the gate's bounds: a
// non-positive limit becomes the default, a limit past the ceiling is
// capped at it, and a negative offset is floored at zero.
func boundPage(limit, offset int) (int, int) {
	switch {
	case limit <= 0:
		limit = DefaultPageSize
	case limit > MaxPageSize:
		limit = MaxPageSize
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}
