package main

import (
	"strings"
	"testing"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/backup"
	"github.com/bensyverson/kura/internal/jobs"
	"github.com/bensyverson/kura/internal/storage"
)

// backupEnv is a complete set of the variables buildBackupService needs to
// wire a production backup Service: the DO Spaces connection, the backups
// bucket, the backup-encryption key, and the database to dump.
func backupEnv() map[string]string {
	return map[string]string{
		"KURA_DO_SPACES_ENDPOINT":       "nyc3.digitaloceanspaces.com",
		"KURA_DO_SPACES_REGION":         "nyc3",
		"KURA_DO_SPACES_ACCESS_KEY":     "spaces-access-key",
		"KURA_DO_SPACES_SECRET_KEY":     "spaces-secret-key",
		"KURA_DO_SPACES_BACKUPS_BUCKET": "client-backups",
		"KURA_BACKUP_ENCRYPTION_KEY":    "a-high-entropy-backup-secret",
		"KURA_DATABASE_URL":             "postgres://u:p@db.internal:5432/kura?sslmode=require",
	}
}

func testRecorder() *audit.Recorder {
	return audit.NewRecorder(audit.NewMemStore())
}

// With no Spaces endpoint configured, backups are simply off: the seam
// returns a nil Service and no error, so no backup/restore kinds register
// and the dev/bare path is unaffected.
func TestBuildBackupServiceNilWhenSpacesUnconfigured(t *testing.T) {
	svc, err := buildBackupService(func(string) string { return "" }, testRecorder())
	if err != nil {
		t.Fatalf("buildBackupService with no Spaces config: %v", err)
	}
	if svc != nil {
		t.Errorf("buildBackupService returned a Service when Spaces was unconfigured")
	}
}

// Opting in by setting the endpoint makes the companions required: a
// missing bucket name is a loud error, not a silently half-wired Service.
func TestBuildBackupServiceRequiresBucketWhenSpacesConfigured(t *testing.T) {
	env := backupEnv()
	delete(env, "KURA_DO_SPACES_BACKUPS_BUCKET")
	_, err := buildBackupService(func(k string) string { return env[k] }, testRecorder())
	if err == nil {
		t.Fatal("buildBackupService accepted a Spaces endpoint with no backups bucket")
	}
	if !strings.Contains(err.Error(), "KURA_DO_SPACES_BACKUPS_BUCKET") {
		t.Errorf("error = %q, want it to name KURA_DO_SPACES_BACKUPS_BUCKET", err)
	}
}

// Backups dump a database, so configuring a destination with no database
// to back up is a configuration error.
func TestBuildBackupServiceRequiresDatabaseURLWhenSpacesConfigured(t *testing.T) {
	env := backupEnv()
	delete(env, "KURA_DATABASE_URL")
	_, err := buildBackupService(func(k string) string { return env[k] }, testRecorder())
	if err == nil {
		t.Fatal("buildBackupService accepted a Spaces endpoint with no database URL")
	}
	if !strings.Contains(err.Error(), "KURA_DATABASE_URL") {
		t.Errorf("error = %q, want it to name KURA_DATABASE_URL", err)
	}
}

// With the full environment, buildBackupService assembles a Service whose
// Store is the append-only backups bucket and whose key is the derived
// 32-byte AES-256 key — and registering it exposes the backup/restore
// kinds so POST /api/jobs can run them.
func TestBuildBackupServiceWiresServiceWhenConfigured(t *testing.T) {
	env := backupEnv()
	svc, err := buildBackupService(func(k string) string { return env[k] }, testRecorder())
	if err != nil {
		t.Fatalf("buildBackupService: %v", err)
	}
	if svc == nil {
		t.Fatal("buildBackupService returned nil with a complete environment")
	}
	if svc.Store == nil || svc.Store.Role() != storage.AppendOnly {
		t.Errorf("Store role = %v, want a non-nil AppendOnly store", svc.Store)
	}
	if svc.Store.Spec().CredentialDomain != storage.BackupsSpec().CredentialDomain {
		t.Errorf("Store spec = %+v, want the backups bucket spec", svc.Store.Spec())
	}
	if svc.DSN != env["KURA_DATABASE_URL"] {
		t.Errorf("DSN = %q, want %q", svc.DSN, env["KURA_DATABASE_URL"])
	}
	if len(svc.Key) != 32 {
		t.Errorf("Key length = %d, want 32 (AES-256)", len(svc.Key))
	}
	if svc.Dumper == nil {
		t.Error("Dumper is nil; want a PGDumper")
	}

	mgr := jobs.NewManager(jobs.NewMemStore())
	svc.Register(mgr)
	kinds := mgr.Kinds()
	for _, want := range []string{backup.KindBackup, backup.KindRestore} {
		found := false
		for _, k := range kinds {
			if k == want {
				found = true
			}
		}
		if !found {
			t.Errorf("kind %q not registered; kinds = %v", want, kinds)
		}
	}
}
