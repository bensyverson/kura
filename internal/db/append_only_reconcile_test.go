package db

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bensyverson/kura/internal/audit"
)

// appendOnlySet reads the frozen entities for a tenant directly.
func appendOnlySet(ctx context.Context, t *testing.T, env testEnv, tenant string) map[string]bool {
	t.Helper()
	rows, err := env.DB.QueryContext(ctx,
		`SELECT entity FROM kura.append_only_entities WHERE tenant_id = $1`, tenant)
	if err != nil {
		t.Fatalf("reading append-only set: %v", err)
	}
	defer rows.Close()
	got := map[string]bool{}
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			t.Fatalf("scanning append-only set: %v", err)
		}
		got[e] = true
	}
	return got
}

// countAudit returns how many events match an action+outcome.
func countAudit(ctx context.Context, t *testing.T, store *audit.MemStore, action string, outcome audit.Outcome) int {
	t.Helper()
	events, err := store.Query(ctx, audit.Filter{Action: action})
	if err != nil {
		t.Fatalf("querying audit: %v", err)
	}
	n := 0
	for _, e := range events {
		if e.Outcome == outcome {
			n++
		}
	}
	return n
}

func insertRecord(ctx context.Context, t *testing.T, env testEnv, tenant, entity string) {
	t.Helper()
	conn := tenantConn(ctx, t, env.DB, tenant)
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO kura.records (tenant_id, entity) VALUES ($1, $2)`, tenant, entity); err != nil {
		t.Fatalf("inserting %s record: %v", entity, err)
	}
}

// TestReconcileAddsProtectionAndIsIdempotent: the desired set from the
// manifest is applied automatically, every addition is audited, and a second
// reconcile with the same desired set is a no-op (no new changes, no error).
func TestReconcileAddsProtectionAndIsIdempotent(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	if err := Migrate(ctx, env.DB); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	tenant := newUUID(ctx, t, env.DB)
	store := audit.NewMemStore()
	rec := audit.NewRecorder(store)

	if err := ReconcileAppendOnly(ctx, env.DB, tenant, []string{"event", "log"}, rec, false); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	got := appendOnlySet(ctx, t, env, tenant)
	if !got["event"] || !got["log"] || len(got) != 2 {
		t.Errorf("append-only set = %v, want {event, log}", got)
	}
	if n := countAudit(ctx, t, store, "append_only.protect", audit.OutcomeAllowed); n != 2 {
		t.Errorf("protect audits = %d, want 2", n)
	}

	// Idempotent: same desired set adds nothing.
	if err := ReconcileAppendOnly(ctx, env.DB, tenant, []string{"event", "log"}, rec, false); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if n := countAudit(ctx, t, store, "append_only.protect", audit.OutcomeAllowed); n != 2 {
		t.Errorf("protect audits after idempotent reconcile = %d, want still 2", n)
	}
}

// TestReconcileRefusesLooseningWithRows: dropping append_only from an entity
// that already has stored records is refused without an override — the
// boundary cannot be weakened as a silent side effect of a manifest edit —
// the row stays protected, and the refusal is audited.
func TestReconcileRefusesLooseningWithRows(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	if err := Migrate(ctx, env.DB); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	tenant := newUUID(ctx, t, env.DB)
	rec := audit.NewRecorder(audit.NewMemStore())
	if err := ReconcileAppendOnly(ctx, env.DB, tenant, []string{"event"}, rec, false); err != nil {
		t.Fatalf("seeding protection: %v", err)
	}
	insertRecord(ctx, t, env, tenant, "event")

	store := audit.NewMemStore()
	err := ReconcileAppendOnly(ctx, env.DB, tenant, []string{}, audit.NewRecorder(store), false)
	if err == nil {
		t.Fatal("reconcile loosened a protected entity with stored rows without an override")
	}
	if !errors.Is(err, ErrAppendOnlyLooseningRefused) {
		t.Errorf("error %v is not ErrAppendOnlyLooseningRefused", err)
	}
	if !strings.Contains(err.Error(), "event") {
		t.Errorf("error %q does not name the entity", err)
	}
	if got := appendOnlySet(ctx, t, env, tenant); !got["event"] {
		t.Error("protection was removed despite the refusal")
	}
	if n := countAudit(ctx, t, store, "append_only.unprotect", audit.OutcomeDenied); n != 1 {
		t.Errorf("denied unprotect audits = %d, want 1", n)
	}
}

// TestReconcileLoosensEmptyEntity: an append-only entity with no stored rows
// can be loosened freely (no override needed), and the change is audited.
func TestReconcileLoosensEmptyEntity(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	if err := Migrate(ctx, env.DB); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	tenant := newUUID(ctx, t, env.DB)
	if err := ReconcileAppendOnly(ctx, env.DB, tenant, []string{"event"}, audit.NewRecorder(audit.NewMemStore()), false); err != nil {
		t.Fatalf("seeding protection: %v", err)
	}

	store := audit.NewMemStore()
	if err := ReconcileAppendOnly(ctx, env.DB, tenant, []string{}, audit.NewRecorder(store), false); err != nil {
		t.Fatalf("loosening an empty entity should succeed: %v", err)
	}
	if got := appendOnlySet(ctx, t, env, tenant); got["event"] {
		t.Error("empty entity was not loosened")
	}
	if n := countAudit(ctx, t, store, "append_only.unprotect", audit.OutcomeAllowed); n != 1 {
		t.Errorf("allowed unprotect audits = %d, want 1", n)
	}
}

// TestReconcileLoosensWithOverride: with the explicit operator override, an
// entity that has stored rows can be loosened, and the change is audited.
func TestReconcileLoosensWithOverride(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	if err := Migrate(ctx, env.DB); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	tenant := newUUID(ctx, t, env.DB)
	if err := ReconcileAppendOnly(ctx, env.DB, tenant, []string{"event"}, audit.NewRecorder(audit.NewMemStore()), false); err != nil {
		t.Fatalf("seeding protection: %v", err)
	}
	insertRecord(ctx, t, env, tenant, "event")

	store := audit.NewMemStore()
	if err := ReconcileAppendOnly(ctx, env.DB, tenant, []string{}, audit.NewRecorder(store), true); err != nil {
		t.Fatalf("loosening with override should succeed: %v", err)
	}
	if got := appendOnlySet(ctx, t, env, tenant); got["event"] {
		t.Error("override did not loosen the entity")
	}
	if n := countAudit(ctx, t, store, "append_only.unprotect", audit.OutcomeAllowed); n != 1 {
		t.Errorf("allowed unprotect audits = %d, want 1", n)
	}
}
