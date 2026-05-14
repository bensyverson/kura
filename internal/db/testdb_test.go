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
	const pw = "kura-test-role-pw"
	if _, err := env.DB.ExecContext(ctx,
		fmt.Sprintf(`ALTER ROLE %s LOGIN PASSWORD %s`, quoteIdent(role), quoteLiteral(pw))); err != nil {
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
