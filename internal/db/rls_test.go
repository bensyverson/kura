package db

import (
	"context"
	"testing"
)

// TestRLSDeniesCrossTenantRead covers the build-plan criterion that RLS is
// enabled on multi-tenant tables and a cross-tenant read is denied. It runs
// as kura_api, not the cluster superuser: superusers bypass RLS regardless
// of FORCE, so the test must use a component role to exercise the policies
// the way the running API server does.
func TestRLSDeniesCrossTenantRead(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	if err := Migrate(ctx, env.DB); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	api := connectAsRole(ctx, t, env, "kura_api")

	tenantA := newUUID(ctx, t, env.DB)
	tenantB := newUUID(ctx, t, env.DB)

	// Tenant A inserts a record on a connection scoped to tenant A.
	connA := tenantConn(ctx, t, api, tenantA)
	var recordID string
	if err := connA.QueryRowContext(ctx,
		`INSERT INTO kura.records (tenant_id, entity) VALUES ($1, 'client') RETURNING id`,
		tenantA).Scan(&recordID); err != nil {
		t.Fatalf("tenant A inserting record: %v", err)
	}

	// Tenant A sees its own record.
	var n int
	if err := connA.QueryRowContext(ctx,
		`SELECT count(*) FROM kura.records WHERE id = $1`, recordID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("tenant A sees %d of its own records, want 1", n)
	}

	// Tenant B, on a connection scoped to tenant B, cannot see it.
	connB := tenantConn(ctx, t, api, tenantB)
	if err := connB.QueryRowContext(ctx,
		`SELECT count(*) FROM kura.records WHERE id = $1`, recordID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("tenant B sees %d of tenant A's records, want 0 — RLS failed to isolate tenants", n)
	}

	// A connection that never sets the tenant GUC sees nothing: the
	// policies fail closed.
	bare, err := api.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer bare.Close()
	if err := bare.QueryRowContext(ctx,
		`SELECT count(*) FROM kura.records`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a connection with no tenant GUC sees %d records, want 0 — RLS must fail closed", n)
	}

	// RLS is enabled and forced on every tenant-scoped table.
	for _, table := range []string{"records", "record_field_values", "pii_spans"} {
		var enabled, forced bool
		if err := env.DB.QueryRowContext(ctx,
			`SELECT relrowsecurity, relforcerowsecurity
			   FROM pg_class WHERE oid = ('kura.' || $1)::regclass`,
			table).Scan(&enabled, &forced); err != nil {
			t.Fatalf("inspecting RLS on kura.%s: %v", table, err)
		}
		if !enabled {
			t.Errorf("kura.%s does not have row-level security enabled", table)
		}
		if !forced {
			t.Errorf("kura.%s does not have row-level security forced", table)
		}
	}
}
