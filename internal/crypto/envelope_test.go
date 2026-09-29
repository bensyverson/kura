package crypto_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/bensyverson/kura/internal/crypto"
)

// mustDEK fails the test if a DEK cannot be generated.
func mustDEK(t *testing.T) []byte {
	t.Helper()
	dek, err := crypto.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	return dek
}

func TestGenerateDEKSizeAndRandomness(t *testing.T) {
	a := mustDEK(t)
	if len(a) != crypto.DEKSize {
		t.Fatalf("GenerateDEK len = %d, want %d", len(a), crypto.DEKSize)
	}
	b := mustDEK(t)
	if bytes.Equal(a, b) {
		t.Fatal("two GenerateDEK calls returned identical keys; not random")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	dek := mustDEK(t)
	for _, plaintext := range [][]byte{
		[]byte("ada@example.com"),
		[]byte(""), // empty value must round-trip too
		bytes.Repeat([]byte{0x00}, 1024),
	} {
		ct, err := crypto.Encrypt(dek, plaintext)
		if err != nil {
			t.Fatalf("Encrypt(%q): %v", plaintext, err)
		}
		got, err := crypto.Decrypt(dek, ct)
		if err != nil {
			t.Fatalf("Decrypt(%q): %v", plaintext, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("round-trip = %q, want %q", got, plaintext)
		}
	}
}

func TestEncryptIsRandomized(t *testing.T) {
	dek := mustDEK(t)
	pt := []byte("same plaintext")
	c1, err := crypto.Encrypt(dek, pt)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	c2, err := crypto.Encrypt(dek, pt)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Equal(c1, c2) {
		t.Fatal("identical plaintext produced identical ciphertext; nonce is not random")
	}
}

func TestDecryptWrongDEKFailsAuthentication(t *testing.T) {
	dek := mustDEK(t)
	ct, err := crypto.Encrypt(dek, []byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	other := mustDEK(t)
	if _, err := crypto.Decrypt(other, ct); !errors.Is(err, crypto.ErrAuthentication) {
		t.Fatalf("Decrypt with wrong DEK err = %v, want ErrAuthentication", err)
	}
}

func TestDecryptTamperedFailsAuthentication(t *testing.T) {
	dek := mustDEK(t)
	ct, err := crypto.Encrypt(dek, []byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ct[len(ct)-1] ^= 0xFF // flip a ciphertext/tag byte
	if _, err := crypto.Decrypt(dek, ct); !errors.Is(err, crypto.ErrAuthentication) {
		t.Fatalf("Decrypt of tampered ciphertext err = %v, want ErrAuthentication", err)
	}
}

func TestDecryptTruncatedReturnsErrorNotPanic(t *testing.T) {
	dek := mustDEK(t)
	// Shorter than a GCM nonce: must error cleanly rather than panic.
	if _, err := crypto.Decrypt(dek, []byte{0x01, 0x02}); err == nil {
		t.Fatal("Decrypt of truncated ciphertext returned nil error")
	}
}

func TestWrapUnwrapRoundTrip(t *testing.T) {
	kek := mustDEK(t) // any 32-byte key works as a KEK
	dek := mustDEK(t)
	wrapped, err := crypto.WrapDEK(kek, dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	if bytes.Equal(wrapped, dek) {
		t.Fatal("wrapped DEK equals the raw DEK; not encrypted")
	}
	got, err := crypto.UnwrapDEK(kek, wrapped)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatalf("unwrapped DEK = %x, want %x", got, dek)
	}
}

func TestUnwrapWrongKEKFailsAuthentication(t *testing.T) {
	kek := mustDEK(t)
	dek := mustDEK(t)
	wrapped, err := crypto.WrapDEK(kek, dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	wrongKEK := mustDEK(t)
	if _, err := crypto.UnwrapDEK(wrongKEK, wrapped); !errors.Is(err, crypto.ErrAuthentication) {
		t.Fatalf("UnwrapDEK with wrong KEK err = %v, want ErrAuthentication", err)
	}
}

func TestInvalidKeySizesRejected(t *testing.T) {
	short := make([]byte, 16) // AES-128-sized: not allowed, we mandate AES-256
	dek := mustDEK(t)
	ct, err := crypto.Encrypt(dek, []byte("x"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	wrapped, err := crypto.WrapDEK(dek, dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	cases := []struct {
		name string
		err  error
	}{
		{"Encrypt", func() error { _, e := crypto.Encrypt(short, []byte("x")); return e }()},
		{"Decrypt", func() error { _, e := crypto.Decrypt(short, ct); return e }()},
		{"WrapDEK", func() error { _, e := crypto.WrapDEK(short, dek); return e }()},
		{"UnwrapDEK", func() error { _, e := crypto.UnwrapDEK(short, wrapped); return e }()},
	}
	for _, tc := range cases {
		if !errors.Is(tc.err, crypto.ErrInvalidKeySize) {
			t.Errorf("%s with 16-byte key err = %v, want ErrInvalidKeySize", tc.name, tc.err)
		}
	}
}
