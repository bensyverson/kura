package backup

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/db"
	"github.com/bensyverson/kura/internal/storage"
)

// TestBackupRestoreRoundTripPostgres is the real-DB proof of the restore
// criterion: dump a seeded source database with pg_dump, encrypt and
// store the dump, then restore it into a throwaway target database with
// pg_restore and verify the rows survived the round trip. It exercises
// PGDumper, AES-GCM encryption, and the storage round trip end to end.
//
// Gated on KURA_TEST_DATABASE_URL like every other integration test, so
// `go test ./...` stays green without a running container.
func TestBackupRestoreRoundTripPostgres(t *testing.T) {
	base := os.Getenv("KURA_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("KURA_TEST_DATABASE_URL not set; skipping integration test")
	}
	ctx := context.Background()

	admin, err := db.Open(base)
	if err != nil {
		t.Fatalf("connecting to test cluster: %v", err)
	}
	// Registered before the per-database drop cleanups so it runs last
	// (t.Cleanup is LIFO): the drops need the admin pool still open.
	t.Cleanup(func() { admin.Close() })

	sourceDSN := createDatabase(t, admin, base)
	targetDSN := createDatabase(t, admin, base)

	// Seed the source with a table and rows.
	src, err := db.Open(sourceDSN)
	if err != nil {
		t.Fatalf("connecting to source: %v", err)
	}
	defer src.Close()
	if _, err := src.ExecContext(ctx, `CREATE TABLE widget (id int primary key, label text)`); err != nil {
		t.Fatalf("creating source table: %v", err)
	}
	if _, err := src.ExecContext(ctx, `INSERT INTO widget (id, label) VALUES (1,'alpha'),(2,'beta'),(3,'gamma')`); err != nil {
		t.Fatalf("seeding source: %v", err)
	}

	store := storage.NewFake(storage.BackupsSpec(), storage.AppendOnly)
	key := DeriveKey("integration-backup-secret")
	rec := audit.NewRecorder(audit.NewMemStore())
	now := func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

	backupSvc := &Service{Dumper: PGDumper{}, Store: store, Key: key, Recorder: rec, DSN: sourceDSN, NowFunc: now}
	restoreSvc := &Service{Dumper: PGDumper{}, Store: store, Key: key, Recorder: rec, DSN: targetDSN, NowFunc: now}

	res, err := backupSvc.Backup(ctx, testActor())
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if err := restoreSvc.Restore(ctx, testActor(), res.ObjectKey); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	// Verify the rows landed in the throwaway target.
	tgt, err := db.Open(targetDSN)
	if err != nil {
		t.Fatalf("connecting to target: %v", err)
	}
	defer tgt.Close()
	rows := map[int]string{}
	res2, err := tgt.QueryContext(ctx, `SELECT id, label FROM widget ORDER BY id`)
	if err != nil {
		t.Fatalf("querying target: %v", err)
	}
	defer res2.Close()
	for res2.Next() {
		var id int
		var label string
		if err := res2.Scan(&id, &label); err != nil {
			t.Fatalf("scanning target row: %v", err)
		}
		rows[id] = label
	}
	want := map[int]string{1: "alpha", 2: "beta", 3: "gamma"}
	if len(rows) != len(want) {
		t.Fatalf("target has %d rows, want %d: %v", len(rows), len(want), rows)
	}
	for id, label := range want {
		if rows[id] != label {
			t.Errorf("row %d = %q, want %q", id, rows[id], label)
		}
	}
}

// createDatabase makes a fresh, uniquely named database on the test
// cluster and returns its DSN. The database is dropped on cleanup.
func createDatabase(t *testing.T, admin *sql.DB, base string) string {
	t.Helper()
	name := fmt.Sprintf("kura_backup_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE DATABASE "` + name + `"`); err != nil {
		t.Fatalf("creating database %s: %v", name, err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(`DROP DATABASE IF EXISTS "` + name + `" WITH (FORCE)`); err != nil {
			t.Logf("dropping database %s: %v", name, err)
		}
	})
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parsing base DSN: %v", err)
	}
	u.Path = "/" + name
	return u.String()
}
