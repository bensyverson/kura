package main

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/backup"
	"github.com/bensyverson/kura/internal/db"
	"github.com/bensyverson/kura/internal/storage"
)

// fakeBackupService builds a minimal backup.Service suitable for asserting
// that the backup/restore job kinds get registered. Register only binds the
// handler closures, so the Service need not be fully operational.
func fakeBackupService() *backup.Service {
	return &backup.Service{
		Store:    storage.NewFake(storage.BackupsSpec(), storage.AppendOnly),
		Recorder: audit.NewRecorder(audit.NewMemStore()),
		Key:      backup.DeriveKey("test-backup-key"),
		DSN:      "postgres://test",
	}
}

// buildJobsManager registers the backup/restore kinds when a backup
// Service is present, so the jobs Manager accepts that work. With no
// Service (the production reality until the Phase 6 object-store client
// lands), no kinds are registered and POST /api/jobs{kind:backup} 400s.
func TestBuildJobsManagerRegistersBackupKindsWhenServicePresent(t *testing.T) {
	mgr, err := buildJobsManager(nil, "", fakeBackupService())
	if err != nil {
		t.Fatalf("buildJobsManager: %v", err)
	}
	kinds := mgr.Kinds()
	for _, want := range []string{backup.KindBackup, backup.KindRestore} {
		if !slices.Contains(kinds, want) {
			t.Errorf("kinds = %v; want it to contain %q", kinds, want)
		}
	}
}

// With no backup Service, the Manager registers no kinds — the graceful
// degradation that keeps kura serve booting before the backups store
// exists.
func TestBuildJobsManagerRegistersNoKindsWithoutService(t *testing.T) {
	mgr, err := buildJobsManager(nil, "", nil)
	if err != nil {
		t.Fatalf("buildJobsManager: %v", err)
	}
	if kinds := mgr.Kinds(); len(kinds) != 0 {
		t.Errorf("kinds = %v; want none when no backup service is wired", kinds)
	}
}

// serveConfig with no backups store configured (the default) brings up a
// Jobs manager with no backup/restore kinds registered, so the server
// boots and a backup submission gets a clear 400 rather than a panic.
func TestServeConfigRegistersNoBackupKindsWithoutStore(t *testing.T) {
	env := serveEnv(t)
	cfg, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("serveConfig: %v", err)
	}
	if cfg.Jobs == nil {
		t.Fatal("cfg.Jobs is nil")
	}
	if kinds := cfg.Jobs.Kinds(); len(kinds) != 0 {
		t.Errorf("cfg.Jobs.Kinds() = %v; want none without a backups store", kinds)
	}
}

// With a database pool, the Manager is backed by the Postgres jobs store —
// the restart-survivable ledger. Proven behaviorally: a job submitted
// through one Manager is visible to a second Manager built over a fresh
// pool to the same database, which only holds for a persistent store.
func TestBuildJobsManagerUsesPostgresWhenPoolPresent(t *testing.T) {
	dsn := freshServeTestDSN(t)
	tenantID := "11111111-1111-1111-1111-111111111111"

	pool, err := db.Open(dsn)
	if err != nil {
		t.Fatalf("opening pool: %v", err)
	}
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	mgr, err := buildJobsManager(pool, tenantID, nil)
	if err != nil {
		t.Fatalf("buildJobsManager: %v", err)
	}
	mgr.Register("noop", func(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
		return nil, nil
	})
	submitted, _, err := mgr.Submit(ctx, "admin@client.com", "noop", "k-1", nil)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	pool2, err := db.Open(dsn)
	if err != nil {
		t.Fatalf("opening second pool: %v", err)
	}
	defer pool2.Close()
	mgr2, err := buildJobsManager(pool2, tenantID, nil)
	if err != nil {
		t.Fatalf("buildJobsManager (second): %v", err)
	}
	got, err := mgr2.Get(ctx, "admin@client.com", submitted.ID)
	if err != nil {
		t.Fatalf("second Manager could not see the job — store is not persistent: %v", err)
	}
	if got.ID != submitted.ID {
		t.Errorf("got job %q; want %q", got.ID, submitted.ID)
	}
}
