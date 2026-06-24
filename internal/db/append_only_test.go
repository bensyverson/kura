package db

import (
	"context"
	"strings"
	"testing"
)

// TestAppendOnlySchemaAndOwnership covers the structural half of the
// append-only enforcement: the set table exists, is tenant-scoped with
// forced RLS, the runtime kura_api role has no access to it, and the guard
// function is SECURITY DEFINER owned by the migrator/owner role (kura_admin)
// so it can read the set the runtime role cannot.
func TestAppendOnlySchemaAndOwnership(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	if err := Migrate(ctx, env.DB); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// The set table has RLS enabled and forced, like every tenant-scoped
	// table.
	var enabled, forced bool
	if err := env.DB.QueryRowContext(ctx,
		`SELECT relrowsecurity, relforcerowsecurity
		   FROM pg_class WHERE oid = 'kura.append_only_entities'::regclass`).
		Scan(&enabled, &forced); err != nil {
		t.Fatalf("inspecting RLS on kura.append_only_entities: %v", err)
	}
	if !enabled || !forced {
		t.Errorf("kura.append_only_entities RLS enabled=%v forced=%v, want both true", enabled, forced)
	}

	// kura_api has no access to the set: it must not be able to declare an
	// entity mutable that the manifest froze.
	for _, priv := range []string{"SELECT", "INSERT", "UPDATE", "DELETE"} {
		var has bool
		if err := env.DB.QueryRowContext(ctx,
			`SELECT has_table_privilege('kura_api', 'kura.append_only_entities', $1)`,
			priv).Scan(&has); err != nil {
			t.Fatalf("checking kura_api %s privilege: %v", priv, err)
		}
		if has {
			t.Errorf("kura_api holds %s on kura.append_only_entities — it must have no access", priv)
		}
	}

	// The guard function is SECURITY DEFINER and owned by kura_admin, so it
	// runs with the owner's rights (which can read the set) rather than the
	// invoking runtime role's.
	var secDef bool
	var owner string
	if err := env.DB.QueryRowContext(ctx,
		`SELECT p.prosecdef, r.rolname
		   FROM pg_proc p
		   JOIN pg_namespace n ON n.oid = p.pronamespace
		   JOIN pg_roles r ON r.oid = p.proowner
		  WHERE n.nspname = 'kura' AND p.proname = 'reject_append_only_mutation'`).
		Scan(&secDef, &owner); err != nil {
		t.Fatalf("inspecting guard function: %v", err)
	}
	if !secDef {
		t.Error("kura.reject_append_only_mutation is not SECURITY DEFINER")
	}
	if owner != "kura_admin" {
		t.Errorf("kura.reject_append_only_mutation owned by %q, want kura_admin", owner)
	}

	// A BEFORE UPDATE OR DELETE trigger guards both record tables.
	for _, table := range []string{"records", "record_field_values"} {
		var n int
		if err := env.DB.QueryRowContext(ctx,
			`SELECT count(*) FROM pg_trigger t
			   JOIN pg_class c ON c.oid = t.tgrelid
			   JOIN pg_namespace nsp ON nsp.oid = c.relnamespace
			  WHERE nsp.nspname = 'kura' AND c.relname = $1 AND NOT t.tgisinternal`,
			table).Scan(&n); err != nil {
			t.Fatalf("inspecting triggers on kura.%s: %v", table, err)
		}
		if n == 0 {
			t.Errorf("kura.%s has no append-only guard trigger", table)
		}
	}
}

// TestAppendOnlyTriggerBlocksRecordMutation proves the trigger fires: once
// an entity is in the append-only set, UPDATE and DELETE of its records
// raise a matchable error rather than mutating the row.
func TestAppendOnlyTriggerBlocksRecordMutation(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	if err := Migrate(ctx, env.DB); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	tenant := newUUID(ctx, t, env.DB)
	api := connectAsRole(ctx, t, env, "kura_api")
	conn := tenantConn(ctx, t, api, tenant)

	var recordID string
	if err := conn.QueryRowContext(ctx,
		`INSERT INTO kura.records (tenant_id, entity) VALUES ($1, 'event') RETURNING id`,
		tenant).Scan(&recordID); err != nil {
		t.Fatalf("inserting record: %v", err)
	}

	// Freeze the entity. kura_api has no access to the set, so the superuser
	// harness writes it (as the migrator/owner would in production).
	if _, err := env.DB.ExecContext(ctx,
		`INSERT INTO kura.append_only_entities (tenant_id, entity) VALUES ($1, 'event')`,
		tenant); err != nil {
		t.Fatalf("seeding append-only set: %v", err)
	}

	// UPDATE is now rejected with a matchable error.
	_, err := conn.ExecContext(ctx,
		`UPDATE kura.records SET updated_at = now() WHERE id = $1`, recordID)
	if err == nil {
		t.Fatal("UPDATE on an append-only record succeeded; the trigger did not fire")
	}
	if !strings.Contains(err.Error(), "append-only") {
		t.Errorf("UPDATE error %q does not identify the append-only violation", err)
	}

	// DELETE is likewise rejected.
	_, err = conn.ExecContext(ctx, `DELETE FROM kura.records WHERE id = $1`, recordID)
	if err == nil {
		t.Fatal("DELETE on an append-only record succeeded; the trigger did not fire")
	}
	if !strings.Contains(err.Error(), "append-only") {
		t.Errorf("DELETE error %q does not identify the append-only violation", err)
	}
}
