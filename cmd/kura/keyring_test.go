package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	"github.com/bensyverson/kura/internal/crypto"
	"github.com/bensyverson/kura/internal/secrets"
)

// kekB64 returns a base64-encoded 32-byte KEK whose every byte is b, so two
// calls with different b yield two distinct, incompatible generations.
func kekB64(b byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, crypto.DEKSize))
}

// backendOf is a secrets.Backend over an in-memory map (the real EnvBackend,
// which reports a missing secret as ErrSecretNotFound).
func backendOf(m map[string]string) secrets.Backend {
	return secrets.NewEnvBackend(func(k string) string { return m[k] })
}

func getenvOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// opensUnder proves the ring's generation `version` is the KEK made of byte b:
// a DEK wrapped by an independent KeyWrapper(b) unwraps through the ring.
func opensUnder(t *testing.T, ring *crypto.KeyRing, version int, b byte) {
	t.Helper()
	w, err := crypto.NewKeyWrapper(bytes.Repeat([]byte{b}, crypto.DEKSize))
	if err != nil {
		t.Fatalf("NewKeyWrapper: %v", err)
	}
	dek, err := crypto.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	wrapped, err := w.Wrap(dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	got, err := ring.Unwrap(wrapped, version)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("ring.Unwrap(v%d) = %x err=%v, want the DEK — wrong key loaded for that generation", version, got, err)
	}
}

// In steady state (no rotation declared) the ring holds a single generation,
// version 1, sourced from the active KEK secret.
func TestBuildKeyRingSteadyState(t *testing.T) {
	backend := backendOf(map[string]string{secrets.EncryptionKeyName: kekB64(0x11)})
	ring, err := buildKeyRing(context.Background(), backend, getenvOf(nil))
	if err != nil {
		t.Fatalf("buildKeyRing: %v", err)
	}
	if ring.ActiveVersion() != 1 {
		t.Errorf("ActiveVersion = %d, want 1", ring.ActiveVersion())
	}
	opensUnder(t, ring, 1, 0x11)
}

// During a rotation the operator declares an active version above a retiring
// one and provides both keys; the ring holds both generations so reads open
// either while writes seal under the active one.
func TestBuildKeyRingLoadsRetiringGeneration(t *testing.T) {
	backend := backendOf(map[string]string{
		secrets.EncryptionKeyName:         kekB64(0x22),
		secrets.EncryptionKeyRetiringName: kekB64(0x11),
	})
	env := getenvOf(map[string]string{"KURA_KEK_VERSION": "2", "KURA_KEK_RETIRING_VERSION": "1"})
	ring, err := buildKeyRing(context.Background(), backend, env)
	if err != nil {
		t.Fatalf("buildKeyRing: %v", err)
	}
	if ring.ActiveVersion() != 2 {
		t.Errorf("ActiveVersion = %d, want 2", ring.ActiveVersion())
	}
	opensUnder(t, ring, 2, 0x22) // active
	opensUnder(t, ring, 1, 0x11) // retiring
}

// A missing active KEK is a clear startup error, not a silent weakening.
func TestBuildKeyRingMissingActiveKeyErrors(t *testing.T) {
	backend := backendOf(map[string]string{})
	if _, err := buildKeyRing(context.Background(), backend, getenvOf(nil)); err == nil {
		t.Fatal("buildKeyRing with no active KEK: want error, got nil")
	}
}

// A retiring generation must precede the active one; declaring it at or above
// the active version is a misconfiguration.
func TestBuildKeyRingRejectsRetiringNotBelowActive(t *testing.T) {
	backend := backendOf(map[string]string{
		secrets.EncryptionKeyName:         kekB64(0x22),
		secrets.EncryptionKeyRetiringName: kekB64(0x11),
	})
	env := getenvOf(map[string]string{"KURA_KEK_VERSION": "2", "KURA_KEK_RETIRING_VERSION": "2"})
	if _, err := buildKeyRing(context.Background(), backend, env); err == nil {
		t.Fatal("retiring version == active: want error, got nil")
	}
}

// Declaring a retiring version but not providing its key is a clear error, not
// a silent single-generation ring that would fail to read half the store.
func TestBuildKeyRingRetiringVersionWithoutKeyErrors(t *testing.T) {
	backend := backendOf(map[string]string{secrets.EncryptionKeyName: kekB64(0x22)})
	env := getenvOf(map[string]string{"KURA_KEK_VERSION": "2", "KURA_KEK_RETIRING_VERSION": "1"})
	if _, err := buildKeyRing(context.Background(), backend, env); err == nil {
		t.Fatal("retiring version declared without its key: want error, got nil")
	}
}

// A non-integer version is a clear configuration error.
func TestBuildKeyRingRejectsNonIntegerVersion(t *testing.T) {
	backend := backendOf(map[string]string{secrets.EncryptionKeyName: kekB64(0x11)})
	env := getenvOf(map[string]string{"KURA_KEK_VERSION": "two"})
	if _, err := buildKeyRing(context.Background(), backend, env); err == nil {
		t.Fatal("non-integer KURA_KEK_VERSION: want error, got nil")
	}
}
