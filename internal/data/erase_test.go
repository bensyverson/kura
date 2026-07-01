package data

import (
	"bytes"
	"context"
	"testing"
)

// PostgresStore satisfies the Eraser interface.
func TestPostgresStoreIsAnEraser(t *testing.T) {
	var _ Eraser = (*PostgresStore)(nil)
}

// The defining property of crypto-shredding: erasing a record destroys its
// field-value DEKs so the encrypted fields can no longer be decrypted (they
// read as erased), while the record and its field-value rows are byte-for-byte
// untouched. That is what makes erasure compatible with append-only entities —
// it never mutates kura.records, so the append-only trigger it would otherwise
// trip never fires. This test freezes the entity, proves the freeze is in
// force, then erases and shows the record survives unchanged.
func TestPostgresStoreEraseShredsKeysLeavingAppendOnlyRecordUntouched(t *testing.T) {
	ctx := context.Background()
	env := newDataTestEnv(t)
	ce := newCryptoEnv(t)
	tenant := newTenantID(t, env)

	// Freeze the entity: any UPDATE/DELETE on its records is now rejected by
	// the append-only trigger (migration 0009).
	freezeEntity(t, env, tenant, "event")

	id := seedRecord(t, env, tenant, "event",
		map[string]string{"kind": "note"},
		map[string]string{"body": "secret PII text"}, ce)

	store := newRecordStore(t, connectAsAPIRole(t, env), tenant, ce)

	// Precondition: the encrypted field decrypts before erasure, and the
	// entity is genuinely frozen (a direct UPDATE is rejected), so the test
	// is exercising the append-only interaction rather than a mutable entity.
	rec, ok, err := store.Get(ctx, "event", id)
	if err != nil || !ok {
		t.Fatalf("Get before erase: ok=%v err=%v", ok, err)
	}
	if rec.Fields["body"] != "secret PII text" {
		t.Fatalf("body before erase = %q, want the decrypted plaintext", rec.Fields["body"])
	}
	if err := attemptRecordUpdate(env, tenant, id); err == nil {
		t.Fatal("append-only entity accepted an UPDATE before erase; the freeze is not in force, so the test proves nothing")
	}

	// Snapshot the at-rest bytes so we can prove erasure never touched them.
	beforeCipher := rawEncryptedValue(t, env, id, "body")
	beforeRecord := recordRowFingerprint(t, env, id)

	// Erase: crypto-shred the record's DEKs.
	n, err := store.Erase(ctx, []string{id})
	if err != nil {
		t.Fatalf("Erase: %v", err)
	}
	if n != 1 {
		t.Errorf("Erase shredded %d keys, want 1 (one encrypted field)", n)
	}

	// The encrypted field now reads as erased — not an error, not ciphertext.
	rec, ok, err = store.Get(ctx, "event", id)
	if err != nil {
		t.Fatalf("Get after erase: %v", err)
	}
	if !ok {
		t.Fatal("record vanished after erase; erasure must not delete the record")
	}
	if _, present := rec.Fields["body"]; present {
		t.Errorf("body is still decryptable after erase: %q", rec.Fields["body"])
	}
	if !contains(rec.Erased, "body") {
		t.Errorf("rec.Erased = %v, want it to name body", rec.Erased)
	}
	if rec.Fields["kind"] != "note" {
		t.Errorf("non-PII field kind = %q, want it intact after erasure", rec.Fields["kind"])
	}

	// The at-rest ciphertext and the record row are byte-identical: erasure
	// destroyed only the external key, never the record. This is exactly why
	// it reaches immutable backups and never trips the append-only trigger.
	if after := rawEncryptedValue(t, env, id, "body"); !bytes.Equal(beforeCipher, after) {
		t.Error("value_encrypted changed after erase; erasure must not mutate the ciphertext")
	}
	if after := recordRowFingerprint(t, env, id); after != beforeRecord {
		t.Errorf("record row changed after erase: %q -> %q", beforeRecord, after)
	}

	// A second erase of an already-shredded record is harmless and idempotent.
	if n, err := store.Erase(ctx, []string{id}); err != nil || n != 0 {
		t.Errorf("second Erase = (%d, %v), want (0, nil) — shredding an erased record is a no-op", n, err)
	}
}
