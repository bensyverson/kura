package crypto_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/bensyverson/kura/internal/crypto"
	"github.com/bensyverson/kura/internal/keystore"
)

// A KeyWrapper is the KEK capability the data layer and the DEK cache depend
// on instead of the raw KEK; it must satisfy both seams.
var (
	_ crypto.Wrapper     = (*crypto.KeyWrapper)(nil)
	_ keystore.Unwrapper = (*crypto.KeyWrapper)(nil)
)

func freshKEK(t *testing.T) []byte {
	t.Helper()
	k, err := crypto.GenerateDEK() // 32 random bytes, the KEK size too
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	return k
}

func TestKeyWrapperRoundTrip(t *testing.T) {
	w, err := crypto.NewKeyWrapper(freshKEK(t))
	if err != nil {
		t.Fatalf("NewKeyWrapper: %v", err)
	}
	dek := freshKEK(t)
	wrapped, err := w.Wrap(dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if bytes.Equal(wrapped, dek) {
		t.Fatal("wrapped DEK equals the raw DEK")
	}
	got, err := w.Unwrap(wrapped)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatalf("Unwrap = %x, want %x", got, dek)
	}
}

func TestNewKeyWrapperRejectsWrongSize(t *testing.T) {
	if _, err := crypto.NewKeyWrapper(make([]byte, 16)); !errors.Is(err, crypto.ErrInvalidKeySize) {
		t.Fatalf("NewKeyWrapper(16 bytes) err = %v, want ErrInvalidKeySize", err)
	}
}

func TestKeyWrapperWrongKEKFailsAuthentication(t *testing.T) {
	w1, _ := crypto.NewKeyWrapper(freshKEK(t))
	w2, _ := crypto.NewKeyWrapper(freshKEK(t))
	wrapped, err := w1.Wrap(freshKEK(t))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if _, err := w2.Unwrap(wrapped); !errors.Is(err, crypto.ErrAuthentication) {
		t.Fatalf("Unwrap under wrong KEK err = %v, want ErrAuthentication", err)
	}
}

func TestParseKEK(t *testing.T) {
	good := base64.StdEncoding.EncodeToString(make([]byte, 32))
	raw, err := crypto.ParseKEK(good)
	if err != nil {
		t.Fatalf("ParseKEK(valid): %v", err)
	}
	if len(raw) != 32 {
		t.Fatalf("ParseKEK len = %d, want 32", len(raw))
	}

	bad := map[string]string{
		"empty":      "",
		"not base64": "!!!not base64!!!",
		"too short":  base64.StdEncoding.EncodeToString(make([]byte, 16)),
		"too long":   base64.StdEncoding.EncodeToString(make([]byte, 48)),
	}
	for name, in := range bad {
		if _, err := crypto.ParseKEK(in); err == nil {
			t.Errorf("ParseKEK(%s) returned nil error, want failure", name)
		}
	}
}

func TestNewKeyWrapperFromBase64(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString(freshKEK(t))
	w, err := crypto.NewKeyWrapperFromBase64(encoded)
	if err != nil {
		t.Fatalf("NewKeyWrapperFromBase64: %v", err)
	}
	// Usable end to end.
	wrapped, err := w.Wrap(freshKEK(t))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if _, err := w.Unwrap(wrapped); err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	// Garbage is rejected at construction.
	if _, err := crypto.NewKeyWrapperFromBase64("garbage"); err == nil {
		t.Fatal("NewKeyWrapperFromBase64(garbage) returned nil error")
	}
}
