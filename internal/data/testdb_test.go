package data

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/bensyverson/kura/internal/crypto"
	"github.com/bensyverson/kura/internal/db"
	"github.com/bensyverson/kura/internal/keystore"
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

// grantKuraAPILogin sets kura_api LOGIN with pw, serialized across
// processes by a transaction-scoped advisory lock taken on the shared base
// database (KURA_TEST_DATABASE_URL). kura_api is cluster-global, so
// parallel `go test ./...` package binaries otherwise race on the same role
// row with "tuple concurrently updated". Advisory lock tags include the
// database OID, so the lock must be taken in the shared base database — not
// a per-test database — to serialize across processes. The lock string
// MUST match the one used by the db and jobs packages so the lock spans all
// three. See internal/db/testdb_test.go (roleLoginAdvisoryLock).
func grantKuraAPILogin(ctx context.Context, pw string) error {
	pool, err := db.Open(os.Getenv("KURA_TEST_DATABASE_URL"))
	if err != nil {
		return fmt.Errorf("open base db for role lock: %w", err)
	}
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin role-login tx: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('kura:test:role-login'))`); err != nil {
		return fmt.Errorf("acquiring role-login advisory lock: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `ALTER ROLE kura_api LOGIN PASSWORD '`+pw+`'`); err != nil {
		return fmt.Errorf("alter role kura_api: %w", err)
	}
	return tx.Commit()
}

// connectAsAPIRole grants kura_api LOGIN with a test password — mirroring
// what the IaC layer does with a secrets-manager value — and returns a
// pool connected as that role. The RecordStore runs as kura_api in
// production: a non-superuser, RLS-bound role, which is what makes the
// tenant-isolation tests meaningful.
func connectAsAPIRole(t *testing.T, env testEnv) *sql.DB {
	t.Helper()
	// kura_api is cluster-global; this password MUST match the value the db
	// and jobs packages set, or a concurrent test that re-sets the password
	// breaks this process's connection (28P01). See grantKuraAPILogin.
	const pw = "kura-test-role-pw"
	if err := grantKuraAPILogin(context.Background(), pw); err != nil {
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

// cryptoEnv bundles the app-layer envelope collaborators a record store
// needs: an in-memory key store (the Fake), the master-KEK wrap capability,
// and the read-side unwrapping cache over that store. One cryptoEnv per
// test gives seedRecord and the store under test a shared key store, so a
// value sealed by the seeder reads back through the store's cache.
type cryptoEnv struct {
	Keys    *keystore.Fake
	Wrapper crypto.Wrapper
	Cache   *keystore.Cache
}

// newCryptoEnv builds a cryptoEnv over a fixed 32-byte test KEK. The Fake
// key store and the cache stay in memory — the key store is a separate
// concern from the record database, so integration tests exercise the real
// main-DB read/write paths against a fake key store without provisioning a
// second cluster (the Postgres key store has its own integration tests).
func newCryptoEnv(t *testing.T) *cryptoEnv {
	t.Helper()
	w, err := crypto.NewKeyWrapper([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewKeyWrapper: %v", err)
	}
	keys := keystore.NewFake()
	return &cryptoEnv{Keys: keys, Wrapper: w, Cache: keystore.NewCache(keys, w, 128)}
}

// seal encrypts value under a fresh per-value DEK and stores the wrapped
// DEK, mirroring the write path's sealField. It returns the ciphertext the
// seeder writes into value_encrypted.
func (ce *cryptoEnv) seal(t *testing.T, tenantID, recordID, field, value string) []byte {
	t.Helper()
	dek, err := crypto.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	ciphertext, err := crypto.Encrypt(dek, []byte(value))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	wrapped, err := ce.Wrapper.Wrap(dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if err := ce.Keys.Store(context.Background(), keystore.Key{
		TenantID: tenantID, RecordID: recordID, FieldName: field,
	}, wrapped); err != nil {
		t.Fatalf("keystore Store: %v", err)
	}
	return ciphertext
}

// newRecordStore builds a PostgresStore over pool, scoped to tenant, with
// ce's crypto collaborators. It fails the test on a construction error.
func newRecordStore(t *testing.T, pool *sql.DB, tenant string, ce *cryptoEnv) *PostgresStore {
	t.Helper()
	s, err := NewPostgresStore(pool, tenant, ce.Keys, ce.Wrapper, ce.Cache)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	return s
}

// seedRecord inserts one record and its field values under tenantID, via
// the superuser pool (which bypasses RLS). plain fields land in value_text;
// encrypted fields are sealed app-layer under a per-value DEK (see
// cryptoEnv.seal) into value_encrypted, exactly as the ingestion path
// stores them. It returns the new record's id.
func seedRecord(t *testing.T, env testEnv, tenantID, entity string, plain, encrypted map[string]string, ce *cryptoEnv) string {
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
		ciphertext := ce.seal(t, tenantID, id, name, val)
		if _, err := env.DB.Exec(
			`INSERT INTO kura.record_field_values (record_id, tenant_id, field_name, field_type, value_encrypted)
			 VALUES ($1, $2, $3, 'text', $4)`,
			id, tenantID, name, ciphertext); err != nil {
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
