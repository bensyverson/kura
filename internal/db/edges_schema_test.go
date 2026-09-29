package db

import (
	"context"
	"strings"
	"testing"
)

// TestRecordEdgesSchema covers migration 0008: kura.record_edges exists with
// both endpoints as real foreign keys into kura.records, forced tenant RLS,
// the two lookup indexes, and kura_api able to read and write it.
func TestRecordEdgesSchema(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	if err := Migrate(ctx, env.DB); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// Both source_record_id and target_record_id are foreign keys into
	// kura.records(id), so an edge can never dangle.
	var fkCount int
	if err := env.DB.QueryRowContext(ctx,
		`SELECT count(*)
		   FROM information_schema.table_constraints tc
		   JOIN information_schema.constraint_column_usage ccu
		     ON tc.constraint_name = ccu.constraint_name
		    AND tc.table_schema = ccu.table_schema
		  WHERE tc.table_schema = 'kura' AND tc.table_name = 'record_edges'
		    AND tc.constraint_type = 'FOREIGN KEY'
		    AND ccu.table_name = 'records' AND ccu.column_name = 'id'`).Scan(&fkCount); err != nil {
		t.Fatalf("counting foreign keys: %v", err)
	}
	if fkCount != 2 {
		t.Errorf("record_edges has %d FKs to records(id), want 2 (source + target)", fkCount)
	}

	// Row-level security is enabled and forced (binds the owner too).
	var rls, forced bool
	if err := env.DB.QueryRowContext(ctx,
		`SELECT relrowsecurity, relforcerowsecurity
		   FROM pg_class WHERE oid = 'kura.record_edges'::regclass`).Scan(&rls, &forced); err != nil {
		t.Fatalf("reading RLS flags: %v", err)
	}
	if !rls || !forced {
		t.Errorf("record_edges RLS enabled=%v forced=%v, want both true", rls, forced)
	}
	var policies int
	if err := env.DB.QueryRowContext(ctx,
		`SELECT count(*) FROM pg_policies
		  WHERE schemaname = 'kura' AND tablename = 'record_edges'`).Scan(&policies); err != nil {
		t.Fatalf("counting policies: %v", err)
	}
	if policies == 0 {
		t.Error("record_edges has no row-level-security policy")
	}

	// The two lookup indexes exist over the expected columns.
	wantIdx := map[string][]string{
		"record_edges_target_idx": {"tenant_id", "target_record_id", "relationship"},
		"record_edges_source_idx": {"tenant_id", "source_record_id"},
	}
	for name, cols := range wantIdx {
		var def string
		if err := env.DB.QueryRowContext(ctx,
			`SELECT indexdef FROM pg_indexes
			  WHERE schemaname = 'kura' AND indexname = $1`, name).Scan(&def); err != nil {
			t.Errorf("index %s: %v", name, err)
			continue
		}
		for _, c := range cols {
			if !strings.Contains(def, c) {
				t.Errorf("index %s def %q is missing column %q", name, def, c)
			}
		}
	}

	// kura_api can read and write the table (via the schema's default privileges).
	for _, priv := range []string{"SELECT", "INSERT"} {
		var ok bool
		if err := env.DB.QueryRowContext(ctx,
			`SELECT has_table_privilege('kura_api', 'kura.record_edges', $1)`, priv).Scan(&ok); err != nil {
			t.Fatalf("has_table_privilege %s: %v", priv, err)
		}
		if !ok {
			t.Errorf("kura_api lacks %s on record_edges", priv)
		}
	}
}
