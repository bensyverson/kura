package db

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

// TestComponentRolesExistWithMinimumPrivilege covers the build-plan
// criterion that per-component users exist with documented minimum
// privileges: kura_api (the API server), kura_admin (provisioning), and
// kura_audit (the tech owner's read-only audit access).
func TestComponentRolesExistWithMinimumPrivilege(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	if err := Migrate(ctx, env.DB); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// All three roles exist, and none is a superuser or bypasses RLS.
	for _, role := range []string{"kura_api", "kura_admin", "kura_audit"} {
		var super, bypassRLS, canLogin bool
		err := env.DB.QueryRowContext(ctx,
			`SELECT rolsuper, rolbypassrls, rolcanlogin FROM pg_roles WHERE rolname = $1`,
			role).Scan(&super, &bypassRLS, &canLogin)
		if errors.Is(err, sql.ErrNoRows) {
			t.Errorf("role %s does not exist", role)
			continue
		}
		if err != nil {
			t.Fatalf("inspecting role %s: %v", role, err)
		}
		if super {
			t.Errorf("role %s is a superuser — component roles must not be", role)
		}
		if bypassRLS {
			t.Errorf("role %s has BYPASSRLS — component roles must stay RLS-bound", role)
		}
	}

	// kura_api can write application data but holds no DDL rights.
	api := connectAsRole(ctx, t, env, "kura_api")
	if _, err := api.ExecContext(ctx, `CREATE TABLE kura.illegal (x integer)`); err == nil {
		t.Error("kura_api was able to CREATE TABLE — it must not hold DDL rights")
	}

	// kura_audit is strictly read-only: it can SELECT but not write.
	audit := connectAsRole(ctx, t, env, "kura_audit")
	if _, err := audit.QueryContext(ctx, `SELECT 1 FROM kura.records`); err != nil {
		t.Errorf("kura_audit cannot SELECT from kura.records: %v", err)
	}
	tenant := newUUID(ctx, t, env.DB)
	if _, err := audit.ExecContext(ctx,
		`INSERT INTO kura.records (tenant_id, entity) VALUES ($1, 'client')`,
		tenant); err == nil {
		t.Error("kura_audit was able to INSERT — it must be read-only")
	}
}
