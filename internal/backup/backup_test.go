package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/identity"
	"github.com/bensyverson/kura/internal/jobs"
	"github.com/bensyverson/kura/internal/secrets"
	"github.com/bensyverson/kura/internal/storage"
)

// fakeDumper stands in for pg_dump/pg_restore: Dump returns a fixed
// payload, Restore records what it was handed so a round-trip test can
// assert the restored bytes equal the dumped bytes.
type fakeDumper struct {
	payload     []byte
	restored    []byte
	restoredDSN string
}

func (f *fakeDumper) Dump(_ context.Context, _ string) ([]byte, error) { return f.payload, nil }
func (f *fakeDumper) Restore(_ context.Context, dsn string, dump []byte) error {
	f.restoredDSN = dsn
	f.restored = append([]byte(nil), dump...)
	return nil
}

func testActor() identity.Principal {
	return identity.Principal{Type: identity.PrincipalAdmin, ID: "admin@client.com", Email: "admin@client.com", Tenant: "client.com"}
}

// newTestService wires a Service over a fakeDumper, an append-only Fake
// backups store, a derived key, and a recorder over an in-memory audit
// store. It returns the service and the audit store for assertions.
func newTestService(t *testing.T, dumper Dumper) (*Service, *audit.MemStore) {
	t.Helper()
	store := storage.NewFake(storage.BackupsSpec(), storage.AppendOnly)
	auditStore := audit.NewMemStore()
	svc := &Service{
		Dumper:   dumper,
		Store:    store,
		Key:      DeriveKey("backup-secret-value"),
		Recorder: audit.NewRecorder(auditStore),
		DSN:      "postgres://ignored/db?sslmode=require",
		NowFunc:  func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	}
	return svc, auditStore
}

// The backup-encryption key name is a real secret name, distinct from the
// runtime field-encryption key — distinct keys are the whole point of the
// independent backup tier.
func TestBackupKeyNameDistinctFromFieldKey(t *testing.T) {
	if secrets.BackupEncryptionKeyName == "" {
		t.Fatal("BackupEncryptionKeyName is empty")
	}
	if secrets.BackupEncryptionKeyName == secrets.EncryptionKeyName {
		t.Errorf("backup key name %q must differ from field key name %q",
			secrets.BackupEncryptionKeyName, secrets.EncryptionKeyName)
	}
}

// Backup dumps the DB, encrypts the dump, and writes it to the backups
// bucket. The stored object is ciphertext (not the plaintext dump) and
// decrypts back to the original dump under the same key.
func TestBackupEncryptsAndStores(t *testing.T) {
	plaintext := []byte("PGDMP fake dump contents")
	svc, _ := newTestService(t, &fakeDumper{payload: plaintext})

	res, err := svc.Backup(context.Background(), testActor())
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if res.ObjectKey == "" {
		t.Fatal("BackupResult.ObjectKey is empty")
	}

	stored, err := svc.Store.Get(context.Background(), res.ObjectKey)
	if err != nil {
		t.Fatalf("Get stored object: %v", err)
	}
	if bytes.Equal(stored, plaintext) {
		t.Error("stored object is the plaintext dump — it was not encrypted")
	}
	if res.Bytes != len(stored) {
		t.Errorf("BackupResult.Bytes = %d, want %d", res.Bytes, len(stored))
	}
	got, err := decrypt(svc.Key, stored)
	if err != nil {
		t.Fatalf("decrypt stored object: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("decrypted object = %q, want %q", got, plaintext)
	}
}

// The backups store is opened append-only, mirroring the deny-delete
// bucket posture the runtime credential holds.
func TestBackupUsesAppendOnlyStore(t *testing.T) {
	svc, _ := newTestService(t, &fakeDumper{payload: []byte("x")})
	if svc.Store.Role() != storage.AppendOnly {
		t.Errorf("backups store role = %v, want AppendOnly", svc.Store.Role())
	}
	if _, err := svc.Backup(context.Background(), testActor()); err != nil {
		t.Fatalf("Backup to append-only store: %v", err)
	}
}

// Restore reads the object, decrypts it, and hands the original dump to
// the dumper's restore against the service's target DSN.
func TestRestoreDecryptsAndRestores(t *testing.T) {
	plaintext := []byte("PGDMP fake dump contents for restore")
	dumper := &fakeDumper{payload: plaintext}
	svc, _ := newTestService(t, dumper)

	res, err := svc.Backup(context.Background(), testActor())
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if err := svc.Restore(context.Background(), testActor(), res.ObjectKey); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if !bytes.Equal(dumper.restored, plaintext) {
		t.Errorf("restored bytes = %q, want %q", dumper.restored, plaintext)
	}
	if dumper.restoredDSN != svc.DSN {
		t.Errorf("restored into DSN %q, want %q", dumper.restoredDSN, svc.DSN)
	}
}

// A Service holding the wrong key cannot decrypt another service's
// backup — GCM authentication fails, proving real encryption rather than
// obfuscation.
func TestRestoreWithWrongKeyFails(t *testing.T) {
	plaintext := []byte("secret dump")
	dumper := &fakeDumper{payload: plaintext}
	svc, _ := newTestService(t, dumper)
	res, err := svc.Backup(context.Background(), testActor())
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}

	wrong := &Service{
		Dumper:   dumper,
		Store:    svc.Store, // same bucket
		Key:      DeriveKey("a-different-secret"),
		Recorder: svc.Recorder,
		DSN:      svc.DSN,
		NowFunc:  svc.NowFunc,
	}
	if err := wrong.Restore(context.Background(), testActor(), res.ObjectKey); err == nil {
		t.Fatal("Restore with the wrong key should fail, got nil")
	}
}

// Both operations write an audit event naming the actor and the object,
// never the contents.
func TestBackupAndRestoreAreAudited(t *testing.T) {
	dumper := &fakeDumper{payload: []byte("dump")}
	svc, auditStore := newTestService(t, dumper)

	res, err := svc.Backup(context.Background(), testActor())
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if err := svc.Restore(context.Background(), testActor(), res.ObjectKey); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	for _, action := range []string{ActionBackupCreated, ActionBackupRestored} {
		events, err := auditStore.Query(context.Background(), audit.Filter{Action: action})
		if err != nil {
			t.Fatalf("Query %s: %v", action, err)
		}
		if len(events) != 1 {
			t.Fatalf("action %q recorded %d times, want 1", action, len(events))
		}
		if events[0].Actor.Email != testActor().Email {
			t.Errorf("event actor = %q, want %q", events[0].Actor.Email, testActor().Email)
		}
	}
}

// Register binds the backup and restore job kinds so a submitted job runs
// through the worker and lands its result on the ledger.
func TestRegisterRunsBackupAsJob(t *testing.T) {
	dumper := &fakeDumper{payload: []byte("dump via job")}
	svc, _ := newTestService(t, dumper)

	mgr := jobs.NewManager(jobs.NewMemStore())
	svc.Register(mgr)

	params, _ := json.Marshal(BackupParams{Actor: testActor()})
	job, _, err := mgr.Submit(context.Background(), testActor().Email, KindBackup, "nightly-1", params)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if _, err := mgr.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	done, err := mgr.Get(context.Background(), testActor().Email, job.ID)
	if err != nil {
		t.Fatalf("Get job: %v", err)
	}
	if done.Status != jobs.StatusSucceeded {
		t.Fatalf("job status = %s, want succeeded (error: %s)", done.Status, done.Error)
	}
	var result BackupResult
	if err := json.Unmarshal(done.Result, &result); err != nil {
		t.Fatalf("decoding job result: %v", err)
	}
	if result.ObjectKey == "" {
		t.Error("job result carries no object key")
	}
}
