package keystore_test

import (
	"context"
	"testing"

	"github.com/bensyverson/kura/internal/keystore"
)

// Store persists the caller-supplied KEK generation rather than a hardcoded
// default, so a value written while a rotation has advanced the active KEK to
// v2 is labelled v2 — not silently mislabelled v1, which would make the next
// rotation try to open a v2-wrapped DEK with the v1 KEK.
func TestFakeStorePersistsSuppliedVersion(t *testing.T) {
	ctx := context.Background()
	store := keystore.NewFake()
	k := keystore.Key{TenantID: "t1", RecordID: "r1", FieldName: "email"}

	if err := store.Store(ctx, k, []byte("wrapped-under-v2"), 2); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if v, ok := store.Version(k); !ok || v != 2 {
		t.Errorf("Version = %d (present=%v), want 2", v, ok)
	}
}

// Fetch returns the stored KEK generation alongside the wrapped DEK, so the
// read path can open the row under the key that wrapped it — the invariant
// that lets a live server read a mixed-version store during a rotation.
func TestFakeFetchReturnsVersion(t *testing.T) {
	ctx := context.Background()
	store := keystore.NewFake()
	k := keystore.Key{TenantID: "t1", RecordID: "r1", FieldName: "email"}
	if err := store.Store(ctx, k, []byte("wrapped-under-v2"), 2); err != nil {
		t.Fatalf("Store: %v", err)
	}

	wrapped, version, found, err := store.Fetch(ctx, k)
	if err != nil || !found {
		t.Fatalf("Fetch: found=%v err=%v", found, err)
	}
	if version != 2 {
		t.Errorf("Fetch version = %d, want 2", version)
	}
	if string(wrapped) != "wrapped-under-v2" {
		t.Errorf("Fetch wrapped = %q, want %q", wrapped, "wrapped-under-v2")
	}
}
