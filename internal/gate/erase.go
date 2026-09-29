package gate

import (
	"context"
	"fmt"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/identity"
)

// Eraser crypto-shreds the DEKs for a set of records, returning how many
// wrapped DEKs were destroyed. The gate invokes it only after the erase
// authorization passes — so it cannot be a way around the gate — and it
// sees only the record ids the request named. It is the erasure-shaped
// sibling of Fetcher and Writer; data.PostgresStore.Erase satisfies it.
type Eraser func(ctx context.Context, recordIDs []string) (int, error)

// EraseRequest is one crypto-shred erasure request through the gate: the
// token to authorize and the records to forget. It carries no tenant — the
// tenant is the authenticated principal's, resolved server-side, never
// asserted by the caller.
type EraseRequest struct {
	Token     string
	RecordIDs []string
}

// EraseResult is what a caller gets back from a successful Erase: the
// resolved principal and the number of wrapped DEKs destroyed.
type EraseResult struct {
	Principal identity.Principal
	Shredded  int
}

// Erase runs the gate chain for a crypto-shred erasure:
//
//	authenticate -> authorize(erase) -> shred -> audit
//
// It is the erasure-shaped sibling of Admin. Erasure destroys keys, not
// rows: the eraser mutates no record, so the operation stays compatible
// with append-only entities and reaches the deny-delete immutable backup.
// A denied request never reaches the eraser; each named record is audited
// distinctly so the trail records exactly which records were forgotten, by
// whom, and when.
func (g *Gate) Erase(ctx context.Context, req EraseRequest, eraser Eraser) (EraseResult, error) {
	principal, err := g.authenticate(ctx, req.Token)
	if err != nil {
		return EraseResult{}, err
	}

	roles, err := g.roles.Roles(ctx, principal)
	if err != nil {
		return EraseResult{}, fmt.Errorf("gate: resolving roles: %w", err)
	}
	allowed := adminActionAllows(AdminErase, roles)

	outcome := audit.OutcomeAllowed
	if !allowed {
		outcome = audit.OutcomeDenied
	}
	if err := g.recorder.RecordAuthorization(ctx, principal, string(AdminErase), audit.Resource{}, outcome); err != nil {
		return EraseResult{}, fmt.Errorf("gate: recording erase authorization: %w", err)
	}
	if !allowed {
		return EraseResult{}, ErrDenied
	}

	shredded, err := eraser(ctx, req.RecordIDs)
	if err != nil {
		return EraseResult{}, fmt.Errorf("gate: erasing: %w", err)
	}

	// Audit each named record distinctly: the erasure trail must name
	// exactly which records were forgotten, not just that an erasure ran.
	for _, id := range req.RecordIDs {
		if err := g.recorder.RecordAccess(ctx, principal, string(AdminErase), audit.Resource{ID: id}); err != nil {
			return EraseResult{}, fmt.Errorf("gate: recording erasure: %w", err)
		}
	}

	return EraseResult{Principal: principal, Shredded: shredded}, nil
}
