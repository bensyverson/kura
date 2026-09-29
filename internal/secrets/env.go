package secrets

import "context"

// EnvBackend is the local/dev Backend: it resolves each secret from the
// process environment (or any injected lookup func), reading the env var
// whose name is exactly the secret name. It is the non-Doppler counterpart
// used when no managed secrets backend is configured — the credential-less
// dev/bare path, parallel to the in-memory data store.
//
// This is not a baked-in secret: the value is read from the runtime
// environment, the same channel Doppler uses when it injects a secret named
// FIELD_ENCRYPTION_KEY as an identically named env var. So a secret resolves
// the same way here as it would under a Doppler-injected process; only the
// source of the injection differs.
type EnvBackend struct {
	lookup func(string) string
}

// NewEnvBackend returns an EnvBackend resolving secrets through lookup
// (typically os.Getenv).
func NewEnvBackend(lookup func(string) string) *EnvBackend {
	return &EnvBackend{lookup: lookup}
}

// Fetch returns the value of the environment variable named name. An unset
// or empty variable is reported as ErrSecretNotFound so a missing secret is
// a clear failure rather than an empty value flowing downstream; an empty
// name is ErrEmptySecretName.
func (b *EnvBackend) Fetch(_ context.Context, name string) (string, error) {
	if name == "" {
		return "", ErrEmptySecretName
	}
	if v := b.lookup(name); v != "" {
		return v, nil
	}
	return "", ErrSecretNotFound
}
