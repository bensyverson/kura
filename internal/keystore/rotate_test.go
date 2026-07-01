package keystore_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/bensyverson/kura/internal/crypto"
	"github.com/bensyverson/kura/internal/keystore"
)

// wrapperOf returns a KeyWrapper over a 32-byte KEK whose every byte is b, so
// two calls with different b yield two distinct, mutually incompatible KEKs.
func wrapperOf(t *testing.T, b byte) *crypto.KeyWrapper {
	t.Helper()
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = b
	}
	w, err := crypto.NewKeyWrapper(kek)
	if err != nil {
		t.Fatalf("NewKeyWrapper: %v", err)
	}
	return w
}

// rewrapVia composes the retiring and incoming wrappers into a Rewrap: unwrap
// under the old KEK, re-wrap under the new one. This is the exact composition
// the eventual operational caller performs; the keystore never sees a KEK.
func rewrapVia(old, incoming crypto.Wrapper) keystore.Rewrap {
	return func(oldWrapped []byte) ([]byte, error) {
		dek, err := old.Unwrap(oldWrapped)
		if err != nil {
			return nil, err
		}
		return incoming.Wrap(dek)
	}
}

// seed is one stored field value: its key, the ciphertext sealed under its
// DEK, and the plaintext, so a test can prove the value still decrypts after
// its DEK is re-wrapped.
type seed struct {
	key    keystore.Key
	sealed []byte
	plain  []byte
}

// seedValues generates n field values, each with a fresh DEK wrapped under w
// and a ciphertext sealed under that DEK, and stores the wrapped DEKs at the
// default version (1). It returns the seeds so a test can re-decrypt later.
func seedValues(t *testing.T, ctx context.Context, store keystore.KeyStore, tenant string, n int, w crypto.Wrapper) []seed {
	t.Helper()
	var seeds []seed
	for i := range n {
		dek, err := crypto.GenerateDEK()
		if err != nil {
			t.Fatalf("GenerateDEK: %v", err)
		}
		plain := fmt.Appendf(nil, "value-%d", i)
		sealed, err := crypto.Encrypt(dek, plain)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		wrapped, err := w.Wrap(dek)
		if err != nil {
			t.Fatalf("Wrap: %v", err)
		}
		key := keystore.Key{TenantID: tenant, RecordID: fmt.Sprintf("r%d", i), FieldName: "f"}
		if err := store.Store(ctx, key, wrapped, 1); err != nil {
			t.Fatalf("Store: %v", err)
		}
		seeds = append(seeds, seed{key: key, sealed: sealed, plain: plain})
	}
	return seeds
}

// After a full rotation every value still decrypts — but only under the new
// KEK, never the retired one — and the ciphertext bytes are untouched
// (rotation never sees them). This is the core crypto-shred-safe property: a
// KEK-only rotation keeps live and backed-up ciphertext decryptable.
func TestRotateReWrapsSoValuesDecryptUnderTheNewKEK(t *testing.T) {
	ctx := context.Background()
	oldW := wrapperOf(t, 0x11)
	newW := wrapperOf(t, 0x22)
	store := keystore.NewFake()
	seeds := seedValues(t, ctx, store, "t1", 3, oldW)

	rotated, err := keystore.Rotate(ctx, store, "t1", 1, 2, 2, rewrapVia(oldW, newW))
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if rotated != 3 {
		t.Errorf("rotated %d, want 3", rotated)
	}

	for _, s := range seeds {
		wrapped, found, err := store.Fetch(ctx, s.key)
		if err != nil || !found {
			t.Fatalf("Fetch(%v): found=%v err=%v", s.key, found, err)
		}
		if _, err := oldW.Unwrap(wrapped); err == nil {
			t.Errorf("%v: wrapped DEK still opens under the retired KEK", s.key)
		}
		dek, err := newW.Unwrap(wrapped)
		if err != nil {
			t.Fatalf("%v: unwrap under new KEK: %v", s.key, err)
		}
		got, err := crypto.Decrypt(dek, s.sealed)
		if err != nil {
			t.Fatalf("%v: decrypt original ciphertext: %v", s.key, err)
		}
		if string(got) != string(s.plain) {
			t.Errorf("%v: decrypt = %q, want %q", s.key, got, s.plain)
		}
		if v, ok := store.Version(s.key); !ok || v != 2 {
			t.Errorf("%v: kek_version = %d (present=%v), want 2", s.key, v, ok)
		}
	}
}

// Rotation is resumable: an interrupted run leaves a mix of advanced and
// pending rows, and simply re-invoking the driver finishes the rest without
// double-wrapping an already-advanced row or skipping a pending one.
func TestRotateIsResumableAcrossInterruptions(t *testing.T) {
	ctx := context.Background()
	oldW := wrapperOf(t, 0x11)
	newW := wrapperOf(t, 0x22)
	store := keystore.NewFake()
	seeds := seedValues(t, ctx, store, "t1", 5, oldW)
	rw := rewrapVia(oldW, newW)

	// An interrupted run: a single batch of two rows advances to v2.
	first, err := store.RotateBatch(ctx, "t1", 1, 2, 2, rw)
	if err != nil {
		t.Fatalf("RotateBatch: %v", err)
	}
	if first != 2 {
		t.Fatalf("first batch rotated %d, want 2", first)
	}

	// Re-invoking the driver finishes exactly the remaining three.
	rest, err := keystore.Rotate(ctx, store, "t1", 1, 2, 2, rw)
	if err != nil {
		t.Fatalf("resumed Rotate: %v", err)
	}
	if rest != 3 {
		t.Errorf("resumed rotation did %d, want the remaining 3", rest)
	}

	// No row remains at v1, and every value decrypts exactly once under the
	// new KEK — a double-wrapped row would fail this decrypt.
	left, err := store.RotateBatch(ctx, "t1", 1, 2, 100, rw)
	if err != nil {
		t.Fatalf("drain check RotateBatch: %v", err)
	}
	if left != 0 {
		t.Errorf("%d rows still at v1 after completion", left)
	}
	for _, s := range seeds {
		wrapped, _, err := store.Fetch(ctx, s.key)
		if err != nil {
			t.Fatalf("Fetch: %v", err)
		}
		dek, err := newW.Unwrap(wrapped)
		if err != nil {
			t.Fatalf("%v: unwrap under new KEK: %v", s.key, err)
		}
		if got, err := crypto.Decrypt(dek, s.sealed); err != nil || string(got) != string(s.plain) {
			t.Errorf("%v: decrypt = %q err=%v, want %q (a double-wrap would break this)", s.key, got, err, s.plain)
		}
		if v, _ := store.Version(s.key); v != 2 {
			t.Errorf("%v: kek_version = %d, want 2", s.key, v)
		}
	}
}

// A rotation that does not advance the version (to <= from) is a
// misconfiguration and is refused, never a silent no-op that could leave the
// operator believing keys were rotated.
func TestRotateBatchRejectsNonAdvancingVersion(t *testing.T) {
	ctx := context.Background()
	store := keystore.NewFake()
	rw := rewrapVia(wrapperOf(t, 0x11), wrapperOf(t, 0x22))
	for _, tc := range []struct{ from, to int }{{2, 2}, {3, 2}} {
		if _, err := store.RotateBatch(ctx, "t1", tc.from, tc.to, 10, rw); !errors.Is(err, keystore.ErrInvalidRotation) {
			t.Errorf("RotateBatch(from=%d,to=%d) err = %v, want ErrInvalidRotation", tc.from, tc.to, err)
		}
	}
}
