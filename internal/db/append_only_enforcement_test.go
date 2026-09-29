package db

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

// seedAppendOnly marks an entity append-only for a tenant, writing the set
// directly (kura_api has no access, so the superuser harness stands in for
// the migrator/owner that writes it in production).
func seedAppendOnly(ctx context.Context, t *testing.T, env testEnv, tenant, entity string) {
	t.Helper()
	if _, err := env.DB.ExecContext(ctx,
		`INSERT INTO kura.append_only_entities (tenant_id, entity) VALUES ($1, $2)`,
		tenant, entity); err != nil {
		t.Fatalf("seeding append-only %q: %v", entity, err)
	}
}

// insertRecordWithField inserts a record of entity with one field value, on a
// tenant-scoped connection, and returns the record id. INSERT is always
// allowed — append-only forbids only later UPDATE/DELETE.
func insertRecordWithField(ctx context.Context, t *testing.T, conn *sql.Conn, tenant, entity string) string {
	t.Helper()
	var id string
	if err := conn.QueryRowContext(ctx,
		`INSERT INTO kura.records (tenant_id, entity) VALUES ($1, $2) RETURNING id`,
		tenant, entity).Scan(&id); err != nil {
		t.Fatalf("inserting %s record: %v", entity, err)
	}
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO kura.record_field_values (record_id, tenant_id, field_name, field_type, value_text)
		 VALUES ($1, $2, 'id', 'string', 'v')`, id, tenant); err != nil {
		t.Fatalf("inserting %s field value: %v", entity, err)
	}
	return id
}

// TestAppendOnlyRejectsMutationViaKuraAPI proves the trigger is complete
// protection: UPDATE and DELETE on both kura.records and
// kura.record_field_values of an append-only entity raise the matchable
// trigger error even via a direct kura_api connection (the runtime role),
// not only through the application.
func TestAppendOnlyRejectsMutationViaKuraAPI(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	if err := Migrate(ctx, env.DB); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	tenant := newUUID(ctx, t, env.DB)
	seedAppendOnly(ctx, t, env, tenant, "event")

	api := connectAsRole(ctx, t, env, "kura_api")
	conn := tenantConn(ctx, t, api, tenant)
	id := insertRecordWithField(ctx, t, conn, tenant, "event")

	mutations := []struct {
		name string
		sql  string
		args []any
	}{
		{"UPDATE records", `UPDATE kura.records SET updated_at = now() WHERE id = $1`, []any{id}},
		{"DELETE records", `DELETE FROM kura.records WHERE id = $1`, []any{id}},
		{"UPDATE field_values", `UPDATE kura.record_field_values SET value_text = 'x' WHERE record_id = $1`, []any{id}},
		{"DELETE field_values", `DELETE FROM kura.record_field_values WHERE record_id = $1`, []any{id}},
	}
	for _, m := range mutations {
		_, err := conn.ExecContext(ctx, m.sql, m.args...)
		if err == nil {
			t.Errorf("%s on an append-only entity succeeded via kura_api; the trigger did not block it", m.name)
			continue
		}
		if !strings.Contains(err.Error(), "append-only") {
			t.Errorf("%s error %q does not identify the append-only violation", m.name, err)
		}
	}
}

// TestAppendOnlyLeavesOtherEntitiesMutable proves the trigger is targeted:
// records and field values of an entity NOT in the append-only set remain
// fully mutable, so the guard freezes only what the manifest froze.
func TestAppendOnlyLeavesOtherEntitiesMutable(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	if err := Migrate(ctx, env.DB); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	tenant := newUUID(ctx, t, env.DB)
	// 'event' is append-only; 'note' is not.
	seedAppendOnly(ctx, t, env, tenant, "event")

	api := connectAsRole(ctx, t, env, "kura_api")
	conn := tenantConn(ctx, t, api, tenant)
	id := insertRecordWithField(ctx, t, conn, tenant, "note")

	if _, err := conn.ExecContext(ctx,
		`UPDATE kura.records SET updated_at = now() WHERE id = $1`, id); err != nil {
		t.Errorf("UPDATE on a non-append-only record was blocked: %v", err)
	}
	if _, err := conn.ExecContext(ctx,
		`UPDATE kura.record_field_values SET value_text = 'updated' WHERE record_id = $1`, id); err != nil {
		t.Errorf("UPDATE on a non-append-only field value was blocked: %v", err)
	}
	if _, err := conn.ExecContext(ctx,
		`DELETE FROM kura.record_field_values WHERE record_id = $1`, id); err != nil {
		t.Errorf("DELETE on a non-append-only field value was blocked: %v", err)
	}
	if _, err := conn.ExecContext(ctx,
		`DELETE FROM kura.records WHERE id = $1`, id); err != nil {
		t.Errorf("DELETE on a non-append-only record was blocked: %v", err)
	}
}
