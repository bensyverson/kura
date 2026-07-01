package keystore_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/bensyverson/kura/internal/keystore"
)

// The Fake is the contract spec for any KeyStore: these tests exercise the
// interface behaviour (store, fetch, miss, shred, tenant scoping) that the
// Postgres implementation must also satisfy.

func key(tenant, record, field string) keystore.Key {
	return keystore.Key{TenantID: tenant, RecordID: record, FieldName: field}
}

func TestFakeImplementsKeyStore(t *testing.T) {
	var _ keystore.KeyStore = keystore.NewFake()
}

func TestStoreThenFetch(t *testing.T) {
	ctx := context.Background()
	ks := keystore.NewFake()
	k := key("t1", "r1", "email")
	wrapped := []byte("wrapped-dek-bytes")

	if err := ks.Store(ctx, k, wrapped, 1); err != nil {
		t.Fatalf("Store: %v", err)
	}
	got, found, err := ks.Fetch(ctx, k)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !found {
		t.Fatal("Fetch found = false after Store, want true")
	}
	if !bytes.Equal(got, wrapped) {
		t.Fatalf("Fetch = %q, want %q", got, wrapped)
	}
}

func TestFetchAbsentIsCleanMiss(t *testing.T) {
	ctx := context.Background()
	ks := keystore.NewFake()
	got, found, err := ks.Fetch(ctx, key("t1", "missing", "email"))
	if err != nil {
		t.Fatalf("Fetch of absent key returned error %v, want clean miss", err)
	}
	if found {
		t.Fatal("Fetch found = true for absent key")
	}
	if got != nil {
		t.Fatalf("Fetch of absent key returned bytes %q, want nil", got)
	}
}

func TestShredDeletesTargetedRecordsOnly(t *testing.T) {
	ctx := context.Background()
	ks := keystore.NewFake()
	// Two records, the first with two fields.
	must(t, ks.Store(ctx, key("t1", "r1", "email"), []byte("d1"), 1))
	must(t, ks.Store(ctx, key("t1", "r1", "phone"), []byte("d2"), 1))
	must(t, ks.Store(ctx, key("t1", "r2", "email"), []byte("d3"), 1))

	deleted, err := ks.Shred(ctx, "t1", []string{"r1"})
	if err != nil {
		t.Fatalf("Shred: %v", err)
	}
	if deleted != 2 {
		t.Fatalf("Shred deleted = %d, want 2 (both of r1's fields)", deleted)
	}
	// r1's keys are gone...
	if _, found, _ := ks.Fetch(ctx, key("t1", "r1", "email")); found {
		t.Error("r1/email still present after shred")
	}
	if _, found, _ := ks.Fetch(ctx, key("t1", "r1", "phone")); found {
		t.Error("r1/phone still present after shred")
	}
	// ...but r2's key is untouched.
	if _, found, _ := ks.Fetch(ctx, key("t1", "r2", "email")); !found {
		t.Error("r2/email was deleted by a shred targeting only r1")
	}
}

func TestTenantIsolation(t *testing.T) {
	ctx := context.Background()
	ks := keystore.NewFake()
	must(t, ks.Store(ctx, key("tenantA", "r1", "email"), []byte("A"), 1))
	must(t, ks.Store(ctx, key("tenantB", "r1", "email"), []byte("B"), 1))

	// One tenant cannot fetch another's DEK, even at the same record/field id.
	got, found, _ := ks.Fetch(ctx, key("tenantA", "r1", "email"))
	if !found || !bytes.Equal(got, []byte("A")) {
		t.Fatalf("tenantA fetch = %q found=%v, want A/true", got, found)
	}

	// Shredding tenantA's record must not touch tenantB's identically-keyed row.
	if _, err := ks.Shred(ctx, "tenantA", []string{"r1"}); err != nil {
		t.Fatalf("Shred: %v", err)
	}
	if _, found, _ := ks.Fetch(ctx, key("tenantB", "r1", "email")); !found {
		t.Error("tenantB's DEK was deleted by a shred scoped to tenantA")
	}
}

func TestStoreRejectsIncompleteKey(t *testing.T) {
	ctx := context.Background()
	ks := keystore.NewFake()
	for _, k := range []keystore.Key{
		key("", "r1", "email"),
		key("t1", "", "email"),
		key("t1", "r1", ""),
	} {
		if err := ks.Store(ctx, k, []byte("d"), 1); !errors.Is(err, keystore.ErrIncompleteKey) {
			t.Errorf("Store(%+v) err = %v, want ErrIncompleteKey", k, err)
		}
	}
}

func TestStoreAndFetchCopyToPreventAliasing(t *testing.T) {
	ctx := context.Background()
	ks := keystore.NewFake()
	k := key("t1", "r1", "email")
	wrapped := []byte("original")
	must(t, ks.Store(ctx, k, wrapped, 1))

	// Mutating the caller's slice after Store must not change stored state.
	wrapped[0] = 'X'
	got, _, _ := ks.Fetch(ctx, k)
	if !bytes.Equal(got, []byte("original")) {
		t.Fatalf("stored value changed via caller's slice: got %q", got)
	}
	// Mutating the returned slice must not corrupt the store either.
	got[0] = 'Y'
	again, _, _ := ks.Fetch(ctx, k)
	if !bytes.Equal(again, []byte("original")) {
		t.Fatalf("stored value changed via returned slice: got %q", again)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
