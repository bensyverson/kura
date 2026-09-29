package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/identity"
)

// ErrAppendOnlyLooseningRefused is returned when reconciliation would have
// to remove append-only protection from an entity that already has stored
// records, and no explicit operator override was given. Removing protection
// is a security-boundary change; it must not happen as a silent side effect
// of a manifest edit.
var ErrAppendOnlyLooseningRefused = errors.New("db: append-only loosening refused")

// appendOnlyActor is the actor recorded for reconciliation events: a service
// principal, since reconciliation is an automatic startup action with no
// human behind it.
var appendOnlyActor = identity.Principal{Type: identity.PrincipalService, ID: "system"}

const (
	auditActionProtect   = "append_only.protect"
	auditActionUnprotect = "append_only.unprotect"
)

// ReconcileAppendOnly brings kura.append_only_entities for a tenant into
// line with the manifest's desired set of append-only entities, on the
// elevated migrator/owner connection. Protection is added automatically
// (the set is tightened silently); protection is removed only when the
// entity has no stored records or an explicit operator override is given —
// otherwise it returns ErrAppendOnlyLooseningRefused and changes nothing, so
// a boundary cannot be weakened by a stray manifest edit. Every change, and
// every refused loosening, is audited.
//
// It runs in a tenant-scoped transaction: append_only_entities and
// kura.records are forced-RLS, so the connection sets the kura.tenant_id GUC
// before touching them. Removals are processed before additions, so a
// refused loosening aborts the whole pass before any change is applied.
func ReconcileAppendOnly(ctx context.Context, pool *sql.DB, tenantID string, desired []string, rec *audit.Recorder, allowLoosen bool) error {
	tx, err := pool.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("db: append-only reconcile: begin: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx,
		`SELECT set_config('kura.tenant_id', $1, true)`, tenantID); err != nil {
		return fmt.Errorf("db: append-only reconcile: set tenant: %w", err)
	}

	rows, err := tx.QueryContext(ctx,
		`SELECT entity FROM kura.append_only_entities WHERE tenant_id = $1`, tenantID)
	if err != nil {
		return fmt.Errorf("db: append-only reconcile: read set: %w", err)
	}
	current := map[string]bool{}
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			rows.Close()
			return fmt.Errorf("db: append-only reconcile: scan: %w", err)
		}
		current[e] = true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("db: append-only reconcile: rows: %w", err)
	}
	rows.Close()

	desiredSet := make(map[string]bool, len(desired))
	for _, e := range desired {
		desiredSet[e] = true
	}

	// Removals first: a refused loosening must abort before any change.
	var toRemove []string
	for e := range current {
		if !desiredSet[e] {
			toRemove = append(toRemove, e)
		}
	}
	sort.Strings(toRemove)
	var removed []string
	for _, e := range toRemove {
		var hasRows bool
		if err := tx.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM kura.records WHERE tenant_id = $1 AND entity = $2)`,
			tenantID, e).Scan(&hasRows); err != nil {
			return fmt.Errorf("db: append-only reconcile: checking rows for %q: %w", e, err)
		}
		if hasRows && !allowLoosen {
			// The refusal is itself a security event: audit it (the audit
			// store is independent of this transaction, so it persists past
			// the rollback) and fail closed.
			_ = rec.RecordAuthorization(ctx, appendOnlyActor, auditActionUnprotect,
				audit.Resource{Entity: e}, audit.OutcomeDenied)
			return fmt.Errorf("db: refusing to remove append-only protection from %q: it has stored records; set KURA_APPEND_ONLY_ALLOW_LOOSEN=true to override: %w", e, ErrAppendOnlyLooseningRefused)
		}
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM kura.append_only_entities WHERE tenant_id = $1 AND entity = $2`,
			tenantID, e); err != nil {
			return fmt.Errorf("db: append-only reconcile: removing %q: %w", e, err)
		}
		removed = append(removed, e)
	}

	var toAdd []string
	for _, e := range desired {
		if !current[e] {
			toAdd = append(toAdd, e)
		}
	}
	sort.Strings(toAdd)
	var added []string
	for _, e := range toAdd {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO kura.append_only_entities (tenant_id, entity) VALUES ($1, $2)`,
			tenantID, e); err != nil {
			return fmt.Errorf("db: append-only reconcile: adding %q: %w", e, err)
		}
		added = append(added, e)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("db: append-only reconcile: commit: %w", err)
	}

	// Audit committed changes after the transaction succeeds, so the log
	// reflects the durable state.
	for _, e := range added {
		_ = rec.RecordAuthorization(ctx, appendOnlyActor, auditActionProtect,
			audit.Resource{Entity: e}, audit.OutcomeAllowed)
	}
	for _, e := range removed {
		_ = rec.RecordAuthorization(ctx, appendOnlyActor, auditActionUnprotect,
			audit.Resource{Entity: e}, audit.OutcomeAllowed)
	}
	return nil
}
