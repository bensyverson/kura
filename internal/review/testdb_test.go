package review

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

// testEnv is one integration test's isolated slice of the test cluster: a
// freshly created, uniquely named database, migrated to current, with a
// superuser pool connected to it.
type testEnv struct {
	DB  *sql.DB
	DSN string
}

// newReviewTestEnv connects to the integration-test Postgres named by
// KURA_TEST_DATABASE_URL, creates a fresh database for the calling test,
// migrates it, and drops it on cleanup. It skips the test when the env var
// is unset, so `go test ./...` stays green without a running container.
func newReviewTestEnv(t *testing.T) testEnv {
	t.Helper()
	base := os.Getenv("KURA_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("KURA_TEST_DATABASE_URL not set; skipping integration test")
	}

	admin, err := db.Open(base)
	if err != nil {
		t.Fatalf("connecting to test cluster: %v", err)
	}
	name := fmt.Sprintf("kura_review_test_%d", time.Now().UnixNano())
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

// grantKuraAPILogin sets kura_api LOGIN with pw, serialized across processes
// by a transaction-scoped advisory lock on the shared base database. The
// lock string and password MUST match the data/db/jobs packages so the lock
// spans all of them (kura_api is cluster-global).
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

// connectAsAPIRole returns a pool connected as the RLS-bound kura_api role,
// which is what makes the tenant-isolation behavior meaningful.
func connectAsAPIRole(t *testing.T, env testEnv) *sql.DB {
	t.Helper()
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
