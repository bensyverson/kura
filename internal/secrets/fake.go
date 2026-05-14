package secrets

import (
	"context"
	"sync"
)

// FakeBackend is an in-memory Backend for tests. It holds secrets set
// explicitly by the test; it never reads from the process environment or
// the filesystem, so a test exercising the secrets path cannot
// accidentally depend on an ambient credential.
type FakeBackend struct {
	mu      sync.Mutex
	secrets map[string]string
}

// NewFakeBackend returns an empty in-memory Backend.
func NewFakeBackend() *FakeBackend {
	return &FakeBackend{secrets: make(map[string]string)}
}

// Set stores value under name. It is a test helper; the production
// Backend has no write path.
func (f *FakeBackend) Set(name, value string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.secrets[name] = value
}

// Fetch returns the value stored under name, or ErrSecretNotFound.
func (f *FakeBackend) Fetch(_ context.Context, name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.secrets[name]
	if !ok {
		return "", ErrSecretNotFound
	}
	return v, nil
}
