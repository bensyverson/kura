package db

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestEncryptValueRejectsEmptyKey(t *testing.T) {
	ctx := context.Background()
	// The empty-key guard runs before any database call, so a nil pool is
	// never dereferenced.
	if _, err := EncryptValue(ctx, nil, "", "secret"); !errors.Is(err, ErrEmptyEncryptionKey) {
		t.Errorf("EncryptValue with empty key = %v, want ErrEmptyEncryptionKey", err)
	}
	if _, err := DecryptValue(ctx, nil, "", nil); !errors.Is(err, ErrEmptyEncryptionKey) {
		t.Errorf("DecryptValue with empty key = %v, want ErrEmptyEncryptionKey", err)
	}
}

func TestEncryptValueRoundTrips(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	if err := Migrate(ctx, env.DB); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	const key = "test-encryption-key"
	const plaintext = "123-45-6789"

	ciphertext, err := EncryptValue(ctx, env.DB, key, plaintext)
	if err != nil {
		t.Fatalf("EncryptValue: %v", err)
	}
	if len(ciphertext) == 0 {
		t.Fatal("ciphertext is empty")
	}
	if bytes.Contains(ciphertext, []byte(plaintext)) {
		t.Fatal("ciphertext contains the plaintext")
	}

	got, err := DecryptValue(ctx, env.DB, key, ciphertext)
	if err != nil {
		t.Fatalf("DecryptValue: %v", err)
	}
	if got != plaintext {
		t.Fatalf("DecryptValue = %q, want %q", got, plaintext)
	}

	// A wrong key must fail loudly, not return garbage plaintext.
	if _, err := DecryptValue(ctx, env.DB, "wrong-key", ciphertext); err == nil {
		t.Fatal("DecryptValue with the wrong key returned nil error")
	}
}
