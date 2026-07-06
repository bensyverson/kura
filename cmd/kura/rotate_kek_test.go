package main

import (
	"bytes"
	"context"
	"strconv"
	"testing"

	"github.com/bensyverson/kura/internal/crypto"
	"github.com/bensyverson/kura/internal/keystore"
)

// wrapperByte builds a KeyWrapper over a 32-byte KEK of all-b, so two bytes
// give two incompatible generations.
func wrapperByte(t *testing.T, b byte) *crypto.KeyWrapper {
	t.Helper()
	w, err := crypto.NewKeyWrapper(bytes.Repeat([]byte{b}, crypto.DEKSize))
	if err != nil {
		t.Fatalf("NewKeyWrapper: %v", err)
	}
	return w
}

// seedWrapped seeds n DEKs wrapped under w at version, returning the raw DEKs
// so a test can prove each still decrypts after rotation.
func seedWrapped(t *testing.T, store *keystore.Fake, tenant string, n int, w crypto.Wrapper, version int) []([]byte) {
	t.Helper()
	deks := make([]([]byte), n)
	for i := range n {
		dek, err := crypto.GenerateDEK()
		if err != nil {
			t.Fatalf("GenerateDEK: %v", err)
		}
		wrapped, err := w.Wrap(dek)
		if err != nil {
			t.Fatalf("Wrap: %v", err)
		}
		k := keystore.Key{TenantID: tenant, RecordID: "r" + strconv.Itoa(i), FieldName: "f"}
		if err := store.Store(context.Background(), k, wrapped, version); err != nil {
			t.Fatalf("Store: %v", err)
		}
		deks[i] = dek
	}
	return deks
}

// The plan derives the source version from the retiring generation and the
// target from the active one, and its rewrap unwraps under the retiring KEK
// and re-wraps under the active one.
func TestBuildRotationPlanDerivesFromToAndRewrap(t *testing.T) {
	backend := backendOf(map[string]string{
		"FIELD_ENCRYPTION_KEY":          kekB64(0x22),
		"FIELD_ENCRYPTION_KEY_RETIRING": kekB64(0x11),
	})
	env := getenvOf(map[string]string{"KURA_KEK_VERSION": "2", "KURA_KEK_RETIRING_VERSION": "1"})

	from, to, rewrap, err := buildRotationPlan(context.Background(), backend, env)
	if err != nil {
		t.Fatalf("buildRotationPlan: %v", err)
	}
	if from != 1 || to != 2 {
		t.Errorf("from/to = %d/%d, want 1/2", from, to)
	}

	// A DEK wrapped under the retiring KEK (0x11), re-wrapped, must open under
	// the active KEK (0x22) — proving the composition unwrap-old -> wrap-new.
	retiring, active := wrapperByte(t, 0x11), wrapperByte(t, 0x22)
	dek, err := crypto.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	oldWrapped, err := retiring.Wrap(dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	newWrapped, err := rewrap(oldWrapped)
	if err != nil {
		t.Fatalf("rewrap: %v", err)
	}
	if got, err := active.Unwrap(newWrapped); err != nil || !bytes.Equal(got, dek) {
		t.Errorf("re-wrapped DEK opens under active = %x err=%v, want the DEK", got, err)
	}
}

// A rotation needs something to rotate away from: with no retiring generation
// declared, planning is a clear error rather than a no-op.
func TestBuildRotationPlanRequiresRetiring(t *testing.T) {
	backend := backendOf(map[string]string{"FIELD_ENCRYPTION_KEY": kekB64(0x22)})
	env := getenvOf(map[string]string{"KURA_KEK_VERSION": "2"})
	if _, _, _, err := buildRotationPlan(context.Background(), backend, env); err == nil {
		t.Fatal("buildRotationPlan with no retiring generation: want error, got nil")
	}
}

// runRotateKEK drives every DEK at the source version to the target, leaving
// each decryptable under the active KEK, and reports the total it rotated.
func TestRunRotateKEKDrivesToCompletion(t *testing.T) {
	tenant := "t1"
	store := keystore.NewFake()
	retiring, active := wrapperByte(t, 0x11), wrapperByte(t, 0x22)
	deks := seedWrapped(t, store, tenant, 4, retiring, 1)
	rewrap := func(old []byte) ([]byte, error) {
		dek, err := retiring.Unwrap(old)
		if err != nil {
			return nil, err
		}
		return active.Wrap(dek)
	}

	var out bytes.Buffer
	total, err := runRotateKEK(context.Background(), store, tenant, 1, 2, 2, rewrap, &out)
	if err != nil {
		t.Fatalf("runRotateKEK: %v", err)
	}
	if total != 4 {
		t.Errorf("rotated %d, want 4", total)
	}
	if out.Len() == 0 {
		t.Error("runRotateKEK produced no progress output")
	}
	for i, dek := range deks {
		k := keystore.Key{TenantID: tenant, RecordID: "r" + strconv.Itoa(i), FieldName: "f"}
		if v, _ := store.Version(k); v != 2 {
			t.Errorf("%v: version = %d, want 2", k, v)
		}
		wrapped, _, _, _ := store.Fetch(context.Background(), k)
		if got, err := active.Unwrap(wrapped); err != nil || !bytes.Equal(got, dek) {
			t.Errorf("%v: opens under active = %x err=%v, want the DEK", k, got, err)
		}
	}
}

// Re-running over a partly-rotated store finishes only the rows still at the
// source version and never double-wraps an already-advanced one (a double
// wrap would break the decrypt), and a further run is a clean no-op.
func TestRunRotateKEKResumesWithoutDoubleWrap(t *testing.T) {
	tenant := "t1"
	store := keystore.NewFake()
	retiring, active := wrapperByte(t, 0x11), wrapperByte(t, 0x22)
	deks := seedWrapped(t, store, tenant, 5, retiring, 1)
	rewrap := func(old []byte) ([]byte, error) {
		dek, err := retiring.Unwrap(old)
		if err != nil {
			return nil, err
		}
		return active.Wrap(dek)
	}

	// Simulate an interrupted run: advance two rows and stop.
	if _, err := store.RotateBatch(context.Background(), tenant, 1, 2, 2, rewrap); err != nil {
		t.Fatalf("partial RotateBatch: %v", err)
	}

	// Resume: only the remaining three advance.
	var out bytes.Buffer
	total, err := runRotateKEK(context.Background(), store, tenant, 1, 2, 2, rewrap, &out)
	if err != nil {
		t.Fatalf("resume runRotateKEK: %v", err)
	}
	if total != 3 {
		t.Errorf("resumed rotation did %d, want the remaining 3", total)
	}

	// Every DEK decrypts exactly once under the active KEK; a double-wrapped
	// row would fail here.
	for i, dek := range deks {
		k := keystore.Key{TenantID: tenant, RecordID: "r" + strconv.Itoa(i), FieldName: "f"}
		wrapped, _, _, _ := store.Fetch(context.Background(), k)
		if got, err := active.Unwrap(wrapped); err != nil || !bytes.Equal(got, dek) {
			t.Errorf("%v: opens under active = %x err=%v, want the DEK (a double-wrap breaks this)", k, got, err)
		}
	}

	// A further run has nothing left to do.
	again, err := runRotateKEK(context.Background(), store, tenant, 1, 2, 2, rewrap, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("no-op runRotateKEK: %v", err)
	}
	if again != 0 {
		t.Errorf("re-run rotated %d, want 0 (already drained)", again)
	}
}
