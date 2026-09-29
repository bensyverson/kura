package data

import (
	"bytes"
	"context"
	"testing"

	"github.com/bensyverson/kura/internal/crypto"
	"github.com/bensyverson/kura/internal/keystore"
)

// wrapperOfByte builds a KeyWrapper over a 32-byte KEK whose every byte is b,
// so two calls with different b yield two distinct, incompatible generations.
func wrapperOfByte(t *testing.T, b byte) *crypto.KeyWrapper {
	t.Helper()
	w, err := crypto.NewKeyWrapper(bytes.Repeat([]byte{b}, crypto.DEKSize))
	if err != nil {
		t.Fatalf("NewKeyWrapper: %v", err)
	}
	return w
}

// sealFieldUnder seals value under wrapper w, records the wrapped DEK at
// version in keys, and inserts the ciphertext field row — the mixed-version
// analogue of cryptoEnv.seal, letting one record hold fields wrapped under
// different KEK generations.
func sealFieldUnder(t *testing.T, env testEnv, keys *keystore.Fake, tenant, recordID, field, value string, w crypto.Wrapper, version int) {
	t.Helper()
	dek, err := crypto.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	ciphertext, err := crypto.Encrypt(dek, []byte(value))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	wrapped, err := w.Wrap(dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if err := keys.Store(context.Background(), keystore.Key{
		TenantID: tenant, RecordID: recordID, FieldName: field,
	}, wrapped, version); err != nil {
		t.Fatalf("keystore Store: %v", err)
	}
	if _, err := env.DB.Exec(
		`INSERT INTO kura.record_field_values (record_id, tenant_id, field_name, field_type, value_encrypted)
		 VALUES ($1, $2, $3, 'text', $4)`,
		recordID, tenant, field, ciphertext); err != nil {
		t.Fatalf("inserting encrypted field %q: %v", field, err)
	}
}

// During a KEK rotation the key store holds a mix of generations: rows still
// wrapped under the retiring KEK (v1) and rows already re-wrapped under the
// active one (v2). A live server must open each row under the key that wrapped
// it. This proves the read path selects the KEK by the row's kek_version
// end-to-end — the read half of a safe online rotation.
func TestPostgresStoreReadsMixedKEKVersions(t *testing.T) {
	env := newDataTestEnv(t)
	tenant := newTenantID(t, env)

	w1 := wrapperOfByte(t, 0x11)
	w2 := wrapperOfByte(t, 0x22)
	ring, err := crypto.NewKeyRing(2, map[int]crypto.Wrapper{1: w1, 2: w2})
	if err != nil {
		t.Fatalf("NewKeyRing: %v", err)
	}
	keys := keystore.NewFake()
	cache := keystore.NewCache(keys, ring, 128)
	store, err := NewPostgresStore(connectAsAPIRole(t, env), tenant, keys, ring, cache)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}

	var id string
	if err := env.DB.QueryRow(
		`INSERT INTO kura.records (tenant_id, entity) VALUES ($1, 'patient') RETURNING id::text`,
		tenant).Scan(&id); err != nil {
		t.Fatalf("inserting record: %v", err)
	}
	sealFieldUnder(t, env, keys, tenant, id, "old_field", "retiring-value", w1, 1)
	sealFieldUnder(t, env, keys, tenant, id, "new_field", "active-value", w2, 2)

	rec, ok, err := store.Get(context.Background(), "patient", id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("record not found")
	}
	if rec.Fields["old_field"] != "retiring-value" {
		t.Errorf("old_field (v1) = %q, want %q — read did not open it under the retiring KEK", rec.Fields["old_field"], "retiring-value")
	}
	if rec.Fields["new_field"] != "active-value" {
		t.Errorf("new_field (v2) = %q, want %q — read did not open it under the active KEK", rec.Fields["new_field"], "active-value")
	}
}
