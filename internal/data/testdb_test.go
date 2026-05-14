package data

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/bensyverson/kura/internal/db"
)

// testEnv is one integration test's isolated slice of the test cluster:
// a freshly created, uniquely named database, migrated to current, with
// a superuser pool connected to it.
type testEnv struct {
	DB  *sql.DB // superuser pool, connected to the fresh per-test database
	DSN string  // DSN of that database, used to derive role-scoped pools
}

// newDataTestEnv connects to the integration-test Postgres named by
// KURA_TEST_DATABASE_URL, creates a fresh database for the calling test,
// migrates it, and drops it on cleanup. It skips the test when the env
// var is unset, so `go test ./...` stays green without a running
// container — bring the container up with `make test-integration`.
func newDataTestEnv(t *testing.T) testEnv {
	t.Helper()
	base := os.Getenv("KURA_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("KURA_TEST_DATABASE_URL not set; skipping integration test")
	}

	admin, err := db.Open(base)
	if err != nil {
		t.Fatalf("connecting to test cluster: %v", err)
	}

	name := fmt.Sprintf("kura_data_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE DATABASE "` + name + `"`); err != nil {
		admin.Close()
		t.Fatalf("creating test database %s: %v", name, err)
	}

	u, err := url.Parse(base)
	if err != nil {
		admin.Close()
		t.Fatalf("parsing KURA_TEST_DATABASE_URL: %v", err)
	}
	u.Path = "/" + name
	dsn := u.String()

	pool, err := db.Open(dsn)
	if err != nil {
		admin.Close()
		t.Fatalf("connecting to test database %s: %v", name, err)
	}

	t.Cleanup(func() {
		pool.Close()
		if _, err := admin.Exec(`DROP DATABASE IF EXISTS "` + name + `" WITH (FORCE)`); err != nil {
			t.Logf("dropping test database %s: %v", name, err)
		}
		admin.Close()
	})

	if err := db.Migrate(context.Background(), pool); err != nil {
		t.Fatalf("migrating test database: %v", err)
	}
	return testEnv{DB: pool, DSN: dsn}
}

// connectAsAPIRole grants kura_api LOGIN with a test password — mirroring
// what the IaC layer does with a secrets-manager value — and returns a
// pool connected as that role. The RecordStore runs as kura_api in
// production: a non-superuser, RLS-bound role, which is what makes the
// tenant-isolation tests meaningful.
func connectAsAPIRole(t *testing.T, env testEnv) *sql.DB {
	t.Helper()
	const pw = "kura-test-api-pw"
	if _, err := env.DB.Exec(`ALTER ROLE kura_api LOGIN PASSWORD '` + pw + `'`); err != nil {
		t.Fatalf("granting LOGIN to kura_api: %v", err)
	}
	u, err := url.Parse(env.DSN)
	if err != nil {
		t.Fatalf("parsing test DSN: %v", err)
	}
	u.User = url.UserPassword("kura_api", pw)
	pool, err := db.Open(u.String())
	if err != nil {
		t.Fatalf("connecting as kura_api: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	return pool
}

// newTenantID asks Postgres for a fresh UUID to use as a tenant id.
func newTenantID(t *testing.T, env testEnv) string {
	t.Helper()
	var id string
	if err := env.DB.QueryRow(`SELECT gen_random_uuid()`).Scan(&id); err != nil {
		t.Fatalf("generating tenant id: %v", err)
	}
	return id
}

// seedRecord inserts one record and its field values under tenantID,
// via the superuser pool (which bypasses RLS). plain fields land in
// value_text; encrypted fields are pgp_sym_encrypt'd under key into
// value_encrypted, exactly as the ingestion path will store them. It
// returns the new record's id.
func seedRecord(t *testing.T, env testEnv, tenantID, entity string, plain, encrypted map[string]string, key string) string {
	t.Helper()
	var id string
	err := env.DB.QueryRow(
		`INSERT INTO kura.records (tenant_id, entity) VALUES ($1, $2) RETURNING id::text`,
		tenantID, entity).Scan(&id)
	if err != nil {
		t.Fatalf("inserting record: %v", err)
	}
	for name, val := range plain {
		if _, err := env.DB.Exec(
			`INSERT INTO kura.record_field_values (record_id, tenant_id, field_name, field_type, value_text)
			 VALUES ($1, $2, $3, 'string', $4)`,
			id, tenantID, name, val); err != nil {
			t.Fatalf("inserting plain field %q: %v", name, err)
		}
	}
	for name, val := range encrypted {
		if _, err := env.DB.Exec(
			`INSERT INTO kura.record_field_values (record_id, tenant_id, field_name, field_type, value_encrypted)
			 VALUES ($1, $2, $3, 'text', pgp_sym_encrypt($4, $5))`,
			id, tenantID, name, val, key); err != nil {
			t.Fatalf("inserting encrypted field %q: %v", name, err)
		}
	}
	return id
}

// rawEncryptedValue returns the raw bytea stored for a field, so a test
// can assert it is genuinely ciphertext and not the plaintext.
func rawEncryptedValue(t *testing.T, env testEnv, recordID, fieldName string) []byte {
	t.Helper()
	var raw []byte
	err := env.DB.QueryRow(
		`SELECT value_encrypted FROM kura.record_field_values WHERE record_id = $1 AND field_name = $2`,
		recordID, fieldName).Scan(&raw)
	if err != nil {
		t.Fatalf("reading raw encrypted value: %v", err)
	}
	return raw
}
