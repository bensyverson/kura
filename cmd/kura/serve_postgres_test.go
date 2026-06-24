package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/bensyverson/kura/internal/data"
	"github.com/bensyverson/kura/internal/db"
	"github.com/bensyverson/kura/internal/migrations"
	"github.com/bensyverson/kura/internal/server"
)

// freshServeTestDSN creates a uniquely named, empty database in the
// integration-test cluster named by KURA_TEST_DATABASE_URL and returns its
// DSN. It does NOT migrate it — exercising that serveConfig migrates the
// configured database itself is the point of the test. The database is
// dropped on cleanup. The test is skipped when the env var is unset, so
// `go test ./...` stays green without a running container.
func freshServeTestDSN(t *testing.T) string {
	t.Helper()
	base := os.Getenv("KURA_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("KURA_TEST_DATABASE_URL not set; skipping integration test")
	}
	admin, err := db.Open(base)
	if err != nil {
		t.Fatalf("connecting to test cluster: %v", err)
	}
	name := fmt.Sprintf("kura_serve_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE DATABASE "` + name + `"`); err != nil {
		admin.Close()
		t.Fatalf("creating test database %s: %v", name, err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(`DROP DATABASE IF EXISTS "` + name + `" WITH (FORCE)`); err != nil {
			t.Logf("dropping test database %s: %v", name, err)
		}
		admin.Close()
	})
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parsing KURA_TEST_DATABASE_URL: %v", err)
	}
	u.Path = "/" + name
	return u.String()
}

// With KURA_DATABASE_URL (and its companion tenant id and encryption key)
// set, serveConfig connects to the configured Postgres database and wires
// the Postgres-backed record and user stores in place of the in-memory
// ones — the dev/E2E path. The resulting Config is one server.New accepts.
func TestServeConfigSelectsPostgresStores(t *testing.T) {
	dsn := freshServeTestDSN(t)
	env := serveEnv(t)
	env["KURA_DATABASE_URL"] = dsn
	env["KURA_DB_TENANT_ID"] = "11111111-1111-1111-1111-111111111111"
	env["KURA_RECORD_ENCRYPTION_KEY"] = "test-record-encryption-key"

	// The migrator/owner connection is a separate required credential. In
	// production it is the kura_admin DSN; the test harness points both the
	// runtime and migrator connections at the same fresh superuser database.
	env["KURA_ADMIN_DATABASE_URL"] = dsn

	cfg, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("serveConfig with KURA_DATABASE_URL: %v", err)
	}
	if _, ok := cfg.Records.(*data.PostgresStore); !ok {
		t.Errorf("Records = %T, want *data.PostgresStore when KURA_DATABASE_URL is set", cfg.Records)
	}
	if _, ok := cfg.Users.(*data.PostgresUserStore); !ok {
		t.Errorf("Users = %T, want *data.PostgresUserStore when KURA_DATABASE_URL is set", cfg.Users)
	}
	if _, err := server.New(cfg); err != nil {
		t.Fatalf("server.New rejected the Postgres-backed config: %v", err)
	}
}

// serveConfig runs migrations against the configured database at startup,
// so an empty database is brought to the current schema before the stores
// read from it. Auto-migration is the only path schema changes reach the
// database — never a manual step — so the wiring must trigger it.
func TestServeConfigMigratesConfiguredDatabase(t *testing.T) {
	dsn := freshServeTestDSN(t)
	env := serveEnv(t)
	env["KURA_DATABASE_URL"] = dsn
	env["KURA_DB_TENANT_ID"] = "11111111-1111-1111-1111-111111111111"
	env["KURA_RECORD_ENCRYPTION_KEY"] = "test-record-encryption-key"
	// Migrations run on the migrator/owner connection; in the test harness it
	// targets the same fresh superuser database as the runtime connection.
	env["KURA_ADMIN_DATABASE_URL"] = dsn

	if _, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] }); err != nil {
		t.Fatalf("serveConfig with KURA_DATABASE_URL: %v", err)
	}

	all, err := migrations.All()
	if err != nil {
		t.Fatalf("loading migrations: %v", err)
	}
	want := all[len(all)-1].Number

	pool, err := db.Open(dsn)
	if err != nil {
		t.Fatalf("connecting to migrated database: %v", err)
	}
	defer pool.Close()
	got, err := db.Version(context.Background(), pool)
	if err != nil {
		t.Fatalf("reading schema version: %v", err)
	}
	if got != want {
		t.Errorf("schema version after serveConfig = %d, want %d — migrations did not run on startup", got, want)
	}
}
