package crypto_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/bensyverson/kura/internal/crypto"
)

// wrappersOf builds a KeyRing over one fresh KEK per version listed, marking
// active as the active version, and returns the ring alongside the raw
// per-version wrappers so a test can prove which key the ring selected.
func wrappersOf(t *testing.T, active int, versions ...int) (*crypto.KeyRing, map[int]*crypto.KeyWrapper) {
	t.Helper()
	raw := make(map[int]*crypto.KeyWrapper, len(versions))
	set := make(map[int]crypto.Wrapper, len(versions))
	for _, v := range versions {
		w, err := crypto.NewKeyWrapper(freshKEK(t))
		if err != nil {
			t.Fatalf("NewKeyWrapper: %v", err)
		}
		raw[v] = w
		set[v] = w
	}
	ring, err := crypto.NewKeyRing(active, set)
	if err != nil {
		t.Fatalf("NewKeyRing: %v", err)
	}
	return ring, raw
}

// WrapActive seals under the active generation's KEK and reports that
// generation, so the write path can stamp the row's kek_version to match the
// key that actually wrapped it.
func TestKeyRingWrapActiveUsesActiveVersion(t *testing.T) {
	ring, raw := wrappersOf(t, 2, 1, 2)
	dek := freshKEK(t)

	wrapped, version, err := ring.WrapActive(dek)
	if err != nil {
		t.Fatalf("WrapActive: %v", err)
	}
	if version != 2 {
		t.Errorf("WrapActive version = %d, want 2 (the active generation)", version)
	}
	if ring.ActiveVersion() != 2 {
		t.Errorf("ActiveVersion = %d, want 2", ring.ActiveVersion())
	}
	// The bytes must open under the active generation's raw key, and not
	// under any other generation's — proving WrapActive used the active KEK.
	if got, err := raw[2].Unwrap(wrapped); err != nil || !bytes.Equal(got, dek) {
		t.Errorf("active key unwrap = %x err=%v, want %x", got, err, dek)
	}
	if _, err := raw[1].Unwrap(wrapped); !errors.Is(err, crypto.ErrAuthentication) {
		t.Errorf("v1 key unwrap of an active-wrapped DEK err = %v, want ErrAuthentication", err)
	}
}

// Unwrap opens a wrapped DEK under the KEK named by the row's version — the
// invariant that lets a live server read a mixed-version store during a
// rotation. Selecting the wrong generation's key fails authentication.
func TestKeyRingUnwrapSelectsByVersion(t *testing.T) {
	ring, raw := wrappersOf(t, 2, 1, 2)
	dek := freshKEK(t)

	v1wrapped, err := raw[1].Wrap(dek)
	if err != nil {
		t.Fatalf("v1 Wrap: %v", err)
	}
	v2wrapped, err := raw[2].Wrap(dek)
	if err != nil {
		t.Fatalf("v2 Wrap: %v", err)
	}

	if got, err := ring.Unwrap(v1wrapped, 1); err != nil || !bytes.Equal(got, dek) {
		t.Errorf("Unwrap(v1) = %x err=%v, want %x", got, err, dek)
	}
	if got, err := ring.Unwrap(v2wrapped, 2); err != nil || !bytes.Equal(got, dek) {
		t.Errorf("Unwrap(v2) = %x err=%v, want %x", got, err, dek)
	}
	// A v1 row asked to open under v2 must fail authentication, proving the
	// ring keyed on the version rather than trying every key.
	if _, err := ring.Unwrap(v1wrapped, 2); !errors.Is(err, crypto.ErrAuthentication) {
		t.Errorf("Unwrap(v1 bytes, version 2) err = %v, want ErrAuthentication", err)
	}
}

// A version the ring does not hold is a clear configuration error — never a
// GCM authentication failure, which would masquerade as data tampering. This
// keeps "operator forgot to load the retiring key" distinct from "this row
// was tampered with".
func TestKeyRingUnknownVersionIsClearError(t *testing.T) {
	ring, _ := wrappersOf(t, 1, 1)

	_, err := ring.Unwrap([]byte("anything"), 99)
	if !errors.Is(err, crypto.ErrUnknownKEKVersion) {
		t.Errorf("Unwrap(unknown version) err = %v, want ErrUnknownKEKVersion", err)
	}
	if errors.Is(err, crypto.ErrAuthentication) {
		t.Error("unknown version reported as an authentication failure; must be distinct")
	}
}

// The active generation must be one the ring actually holds; otherwise the
// write path would stamp a version it cannot itself open. An empty ring is
// likewise rejected.
func TestNewKeyRingRejectsInvalidActive(t *testing.T) {
	w, err := crypto.NewKeyWrapper(freshKEK(t))
	if err != nil {
		t.Fatalf("NewKeyWrapper: %v", err)
	}
	if _, err := crypto.NewKeyRing(3, map[int]crypto.Wrapper{1: w}); err == nil {
		t.Error("NewKeyRing with active=3 absent from the set: want error, got nil")
	}
	if _, err := crypto.NewKeyRing(1, map[int]crypto.Wrapper{}); err == nil {
		t.Error("NewKeyRing with an empty set: want error, got nil")
	}
}
