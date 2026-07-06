package db

import (
	"context"
	"testing"
)

// MigrateKeystore brings a fresh key-store database to its own schema,
// recorded in that instance's own schema_migrations. Physical separation is
// a production property; in tests a second fresh database on the same
// cluster is the correct analogue.
func TestMigrateKeystoreCreatesLineage(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	if err := MigrateKeystore(ctx, env.DB); err != nil {
		t.Fatalf("MigrateKeystore: %v", err)
	}

	// The lineage is recorded in this instance's bookkeeping, numbered from 1.
	v, err := Version(ctx, env.DB)
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if v != 1 {
		t.Fatalf("keystore schema version = %d, want 1", v)
	}

	// The wrapped-DEK table carries the field-value identity plus payload.
	cols := map[string]bool{}
	rows, err := env.DB.QueryContext(ctx,
		`SELECT column_name FROM information_schema.columns
		 WHERE table_schema = 'kura' AND table_name = 'wrapped_deks'`)
	if err != nil {
		t.Fatalf("querying columns: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			t.Fatalf("scan: %v", err)
		}
		cols[c] = true
	}
	for _, want := range []string{"tenant_id", "record_id", "field_name", "wrapped_dek", "kek_version"} {
		if !cols[want] {
			t.Errorf("kura.wrapped_deks is missing column %q", want)
		}
	}

	// Tenant isolation is enforced and binds the owner too (forced RLS),
	// consistent with the main schema.
	var enabled, forced bool
	if err := env.DB.QueryRowContext(ctx,
		`SELECT relrowsecurity, relforcerowsecurity FROM pg_class
		 WHERE oid = 'kura.wrapped_deks'::regclass`).Scan(&enabled, &forced); err != nil {
		t.Fatalf("reading RLS flags: %v", err)
	}
	if !enabled || !forced {
		t.Errorf("kura.wrapped_deks RLS enabled=%v forced=%v, want both true", enabled, forced)
	}

	// Idempotent: re-running applies nothing and does not error.
	if err := MigrateKeystore(ctx, env.DB); err != nil {
		t.Fatalf("second MigrateKeystore: %v", err)
	}
	if v2, _ := Version(ctx, env.DB); v2 != 1 {
		t.Fatalf("version after re-run = %d, want 1", v2)
	}
}
