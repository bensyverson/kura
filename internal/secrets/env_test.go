package secrets

import (
	"context"
	"errors"
	"testing"
)

// EnvBackend resolves a secret from the process environment (or any lookup
// func) under the env var whose name is exactly the secret name — the
// non-Doppler counterpart used on the credential-less dev/bare path.
func TestEnvBackendFetchReturnsSetValue(t *testing.T) {
	env := map[string]string{EncryptionKeyName: "a-secret-value"}
	backend := NewEnvBackend(func(k string) string { return env[k] })

	got, err := backend.Fetch(context.Background(), EncryptionKeyName)
	if err != nil {
		t.Fatalf("Fetch returned error: %v", err)
	}
	if got != "a-secret-value" {
		t.Errorf("Fetch = %q, want %q", got, "a-secret-value")
	}
}

// An unset (empty) variable is reported as ErrSecretNotFound so a missing
// secret is a clear failure rather than an empty value flowing downstream.
func TestEnvBackendFetchUnsetIsNotFound(t *testing.T) {
	backend := NewEnvBackend(func(string) string { return "" })

	_, err := backend.Fetch(context.Background(), EncryptionKeyName)
	if !errors.Is(err, ErrSecretNotFound) {
		t.Errorf("Fetch error = %v, want ErrSecretNotFound", err)
	}
}

// An empty secret name is a programming error, distinct from a missing
// secret: the backend returns ErrEmptySecretName without consulting lookup.
func TestEnvBackendFetchEmptyNameIsError(t *testing.T) {
	backend := NewEnvBackend(func(string) string {
		t.Fatal("lookup must not be consulted for an empty name")
		return ""
	})

	_, err := backend.Fetch(context.Background(), "")
	if !errors.Is(err, ErrEmptySecretName) {
		t.Errorf("Fetch error = %v, want ErrEmptySecretName", err)
	}
}
