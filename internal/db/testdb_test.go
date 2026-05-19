package db

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// testEnv is one integration test's isolated slice of the test cluster: a
// freshly created, uniquely named database and a pool connected to it as
// the cluster superuser.
type testEnv struct {
	DB  *sql.DB // superuser pool, connected to the fresh per-test database
	DSN string  // DSN of that database, used to derive role-scoped pools
}

// newTestEnv connects to the integration-test Postgres named by
// KURA_TEST_DATABASE_URL, creates a fresh uniquely named database for the
// calling test, and drops it on cleanup so tests never share schema or
// data state. It skips the test when the env var is unset, so
// `go test ./...` stays green without a running container — bring the
// container up with `make test-integration` (see scripts/test-db.sh).
//
// KURA_TEST_DATABASE_URL must be a URL-form, TLS-required DSN for a
// superuser: the harness needs CREATE DATABASE, and the migrations need
// CREATE EXTENSION and CREATE ROLE.
func newTestEnv(t *testing.T) testEnv {
	t.Helper()
	base := os.Getenv("KURA_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("KURA_TEST_DATABASE_URL not set; skipping integration test")
	}

	admin, err := Open(base)
	if err != nil {
		t.Fatalf("connecting to test cluster: %v", err)
	}

	name := fmt.Sprintf("kura_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE DATABASE ` + quoteIdent(name)); err != nil {
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

	db, err := Open(dsn)
	if err != nil {
		admin.Close()
		t.Fatalf("connecting to test database %s: %v", name, err)
	}

	t.Cleanup(func() {
		db.Close()
		// FORCE terminates any lingering backend so the drop always lands.
		if _, err := admin.Exec(`DROP DATABASE IF EXISTS ` + quoteIdent(name) + ` WITH (FORCE)`); err != nil {
			t.Logf("dropping test database %s: %v", name, err)
		}
		admin.Close()
	})

	return testEnv{DB: db, DSN: dsn}
}

// connectAsRole grants role LOGIN with a test password — mirroring what the
// IaC layer does with a secrets-manager value — and returns a pool
// connected to the test database as that role. Component roles are created
// NOLOGIN by migration 0003 precisely so no password lives in a committed
// file; the test supplies one here, at run time, the same way provisioning
// does. The returned pool is closed by a t.Cleanup.
func connectAsRole(ctx context.Context, t *testing.T, env testEnv, role string) *sql.DB {
	t.Helper()
	// Canonical shared test password for the cluster-global component roles.
	// The jobs and data packages set kura_api's password to this same value;
	// they must agree, or a concurrent test re-setting the password breaks
	// another process's connection (28P01).
	const pw = "kura-test-role-pw"
	if err := grantRoleLogin(ctx, role, pw); err != nil {
		t.Fatalf("granting LOGIN to %s: %v", role, err)
	}

	u, err := url.Parse(env.DSN)
	if err != nil {
		t.Fatalf("parsing test DSN: %v", err)
	}
	u.User = url.UserPassword(role, pw)

	db, err := Open(u.String())
	if err != nil {
		t.Fatalf("connecting as %s: %v", role, err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// roleLoginAdvisoryLock is the SQL that takes the cross-process lock
// guarding component-role mutation. The component roles (kura_api,
// kura_admin, kura_audit) are cluster-global, so every test database in
// the shared integration cluster targets the same pg_authid rows. Without
// serialization, concurrent `ALTER ROLE … LOGIN PASSWORD` from parallel
// `go test ./...` package binaries collide with "tuple concurrently
// updated" (SQLSTATE XX000). The lock is keyed on a fixed string; the jobs
// and data packages' equivalents use the SAME string so the lock spans all
// three. It is a transaction-scoped lock, released on commit/rollback.
//
// Crucially, the lock is taken on a connection to the *base* database
// (KURA_TEST_DATABASE_URL, i.e. the cluster's shared `postgres` db), not a
// per-test database: advisory lock tags include the database OID, so the
// same key in two different databases is two different locks and would not
// serialize. ALTER ROLE is global and runs from any database, so taking
// both the lock and the ALTER on the shared base connection serializes
// every test process on the cluster.
const roleLoginAdvisoryLock = `SELECT pg_advisory_xact_lock(hashtext('kura:test:role-login'))`

// grantRoleLogin sets role LOGIN with pw, serialized by the shared advisory
// lock above. It returns an error rather than calling t.Fatal so it is safe
// to invoke from concurrent goroutines (TestConcurrentRoleLoginIsSerialized
// does exactly that to guard against the lock being removed or scoped wrong).
func grantRoleLogin(ctx context.Context, role, pw string) error {
	return lockedRoleAlter(ctx, fmt.Sprintf(`ALTER ROLE %s LOGIN PASSWORD %s`, quoteIdent(role), quoteLiteral(pw)))
}

// lockedRoleAlter runs alterSQL (a role mutation) on a connection to the
// shared base database, holding the cross-process advisory lock for the
// duration. See roleLoginAdvisoryLock for why the base database matters.
func lockedRoleAlter(ctx context.Context, alterSQL string) error {
	base := os.Getenv("KURA_TEST_DATABASE_URL")
	pool, err := Open(base)
	if err != nil {
		return fmt.Errorf("open base db for role lock: %w", err)
	}
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin role-login tx: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, roleLoginAdvisoryLock); err != nil {
		return fmt.Errorf("acquiring role-login advisory lock: %w", err)
	}
	if _, err := tx.ExecContext(ctx, alterSQL); err != nil {
		return fmt.Errorf("%s: %w", alterSQL, err)
	}
	return tx.Commit()
}

// tenantConn returns a dedicated connection with the kura.tenant_id GUC set
// to tenantID, so RLS policies on that connection resolve to that tenant.
// The connection is closed by a t.Cleanup.
func tenantConn(ctx context.Context, t *testing.T, db *sql.DB, tenantID string) *sql.Conn {
	t.Helper()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("acquiring connection: %v", err)
	}
	if _, err := conn.ExecContext(ctx,
		`SELECT set_config('kura.tenant_id', $1, false)`, tenantID); err != nil {
		conn.Close()
		t.Fatalf("setting tenant GUC: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// newUUID asks Postgres for a fresh UUID, used to mint tenant identifiers
// in tests.
func newUUID(ctx context.Context, t *testing.T, db *sql.DB) string {
	t.Helper()
	var id string
	if err := db.QueryRowContext(ctx, `SELECT gen_random_uuid()`).Scan(&id); err != nil {
		t.Fatalf("generating uuid: %v", err)
	}
	return id
}

// quoteIdent quotes a Postgres identifier. The identifiers it is given are
// harness-generated (kura_test_<nanos>) or fixed role names, never user
// input.
func quoteIdent(ident string) string {
	return `"` + strings.ReplaceAll(ident, `"`, `""`) + `"`
}

// quoteLiteral quotes a Postgres string literal. Used only for the fixed
// test-role password constant.
func quoteLiteral(s string) string {
	return `'` + strings.ReplaceAll(s, `'`, `''`) + `'`
}
