// Package backup is the independent logical-backup tier: it dumps the
// database, encrypts the dump with a key distinct from the runtime
// field-encryption key, and writes the ciphertext to the separate-region
// BACKUPS bucket through the append-only storage role. Restore reverses
// the path into a target database.
//
// This is the compromise-resilient copy that earns the security
// improvement over bare managed-Postgres backups: DO's built-in managed
// backups share the primary's credential domain, while this tier uses a
// separate bucket, a separate credential, and a separate encryption key.
//
// The orchestration lives here in internal/ per the adapter-over-core
// rule; the CLI and the jobs worker are thin callers. The dump mechanism
// is behind the Dumper interface so the orchestration is unit-testable
// without a database, while PGDumper shells out to pg_dump/pg_restore for
// the real path.
package backup

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/identity"
	"github.com/bensyverson/kura/internal/jobs"
	"github.com/bensyverson/kura/internal/storage"
)

// Audit action names recorded for the two operations. They name the
// actor and the object key, never the dump contents.
const (
	ActionBackupCreated  = "backup.created"
	ActionBackupRestored = "backup.restored"
)

// Job kinds registered with the jobs Manager so backup and restore run
// as durable, idempotent, audited async operations.
const (
	KindBackup  = "backup"
	KindRestore = "restore"
)

// Dumper abstracts the database dump/restore mechanism. The production
// implementation (PGDumper) shells out to pg_dump and pg_restore; tests
// inject a fake. Dump returns the raw dump bytes for a DSN; Restore
// applies a dump to a DSN.
type Dumper interface {
	Dump(ctx context.Context, dsn string) ([]byte, error)
	Restore(ctx context.Context, dsn string, dump []byte) error
}

// Service orchestrates backups and restores for one on-box database. A
// Service is bound to a single DSN: it dumps that database and restores
// into it. To restore one database's backup into a different target
// (disaster recovery, verification), construct a second Service on the
// target DSN sharing the same Store and Key.
type Service struct {
	// Dumper performs the actual dump/restore.
	Dumper Dumper
	// Store is the backups bucket, opened append-only.
	Store storage.Store
	// Key is the 32-byte AES-256 key for the backup dump, derived from
	// the secrets-managed BACKUP_ENCRYPTION_KEY (see DeriveKey).
	Key []byte
	// Recorder writes the audit events.
	Recorder *audit.Recorder
	// DSN is the database this Service dumps and restores into.
	DSN string
	// NowFunc supplies the time used in the object key; defaults to
	// time.Now when nil.
	NowFunc func() time.Time
}

// BackupResult describes a completed backup: the object key in the
// bucket, the encrypted size, and a checksum of the stored ciphertext.
type BackupResult struct {
	ObjectKey string `json:"object_key"`
	Bytes     int    `json:"bytes"`
	SHA256    string `json:"sha256"`
}

// BackupParams is the job payload for a backup. It carries only the
// actor — never a DSN or a credential, which would otherwise be
// persisted in the ledger. The Service already holds the DSN it operates
// on.
type BackupParams struct {
	Actor identity.Principal `json:"actor"`
}

// RestoreParams is the job payload for a restore: the actor and the
// object key to restore. The target DSN is the Service's own.
type RestoreParams struct {
	Actor     identity.Principal `json:"actor"`
	ObjectKey string             `json:"object_key"`
}

// DeriveKey turns a secrets-managed key string of arbitrary length into a
// fixed 32-byte AES-256 key. The backend stores a high-entropy secret, so
// a SHA-256 of it is an appropriate fixed-length derivation — not a
// password stretch, which would call for a slow KDF.
func DeriveKey(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// Backup dumps the Service's database, encrypts the dump under Key, writes
// the ciphertext to the backups bucket under a time-stamped key, and
// records the action. The store is append-only, so each backup writes a
// new object and never overwrites a prior one.
func (s *Service) Backup(ctx context.Context, actor identity.Principal) (BackupResult, error) {
	dump, err := s.Dumper.Dump(ctx, s.DSN)
	if err != nil {
		return BackupResult{}, fmt.Errorf("backup: dumping database: %w", err)
	}
	ciphertext, err := encrypt(s.Key, dump)
	if err != nil {
		return BackupResult{}, fmt.Errorf("backup: encrypting dump: %w", err)
	}
	key := s.objectKey()
	if err := s.Store.Put(ctx, key, ciphertext); err != nil {
		return BackupResult{}, fmt.Errorf("backup: writing to backups bucket: %w", err)
	}
	if err := s.Recorder.RecordAccess(ctx, actor, ActionBackupCreated, audit.Resource{
		Entity: "backup",
		ID:     key,
	}); err != nil {
		return BackupResult{}, fmt.Errorf("backup: recording audit event: %w", err)
	}
	sum := sha256.Sum256(ciphertext)
	return BackupResult{ObjectKey: key, Bytes: len(ciphertext), SHA256: hex.EncodeToString(sum[:])}, nil
}

// Restore reads the named object, decrypts it under Key, restores the
// dump into the Service's database, and records the action.
func (s *Service) Restore(ctx context.Context, actor identity.Principal, objectKey string) error {
	ciphertext, err := s.Store.Get(ctx, objectKey)
	if err != nil {
		return fmt.Errorf("restore: reading from backups bucket: %w", err)
	}
	dump, err := decrypt(s.Key, ciphertext)
	if err != nil {
		return fmt.Errorf("restore: decrypting dump: %w", err)
	}
	if err := s.Dumper.Restore(ctx, s.DSN, dump); err != nil {
		return fmt.Errorf("restore: applying dump: %w", err)
	}
	if err := s.Recorder.RecordAccess(ctx, actor, ActionBackupRestored, audit.Resource{
		Entity: "backup",
		ID:     objectKey,
	}); err != nil {
		return fmt.Errorf("restore: recording audit event: %w", err)
	}
	return nil
}

// Register binds the backup and restore job kinds to this Service's
// handlers so a submitted job runs through the worker, with the ledger
// tracking status and the result.
func (s *Service) Register(mgr *jobs.Manager) {
	mgr.Register(KindBackup, func(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
		var p BackupParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, fmt.Errorf("backup job: decoding params: %w", err)
		}
		res, err := s.Backup(ctx, p.Actor)
		if err != nil {
			return nil, err
		}
		return json.Marshal(res)
	})
	mgr.Register(KindRestore, func(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
		var p RestoreParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, fmt.Errorf("restore job: decoding params: %w", err)
		}
		if err := s.Restore(ctx, p.Actor, p.ObjectKey); err != nil {
			return nil, err
		}
		return json.Marshal(map[string]string{"object_key": p.ObjectKey})
	})
}

// objectKey builds the time-stamped, append-only-safe object key for a
// new backup.
func (s *Service) objectKey() string {
	now := time.Now
	if s.NowFunc != nil {
		now = s.NowFunc
	}
	return fmt.Sprintf("backup-%s.dump.enc", now().UTC().Format("20060102T150405.000000000Z"))
}

// encrypt seals plaintext with AES-256-GCM, prepending the random nonce
// so decrypt is self-contained.
func encrypt(key, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// decrypt opens an AES-256-GCM ciphertext produced by encrypt. A wrong
// key or tampered ciphertext fails authentication.
func decrypt(key, ciphertext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext shorter than nonce")
	}
	nonce, sealed := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("authenticating ciphertext: %w", err)
	}
	return plaintext, nil
}

// newGCM builds an AES-256-GCM AEAD from a 32-byte key.
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("building AES cipher: %w", err)
	}
	return cipher.NewGCM(block)
}
