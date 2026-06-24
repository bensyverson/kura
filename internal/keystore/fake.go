package keystore

import (
	"context"
	"slices"
	"sync"
)

// Fake is an in-memory KeyStore for unit tests of the write, read, and erase
// paths. It implements the identical contract to the Postgres store —
// tenant-scoped, clean misses, set-based shred — so a test that passes
// against the Fake is exercising the same behaviour the production store
// guarantees. It is safe for concurrent use.
type Fake struct {
	mu   sync.Mutex
	keys map[Key][]byte
}

var _ KeyStore = (*Fake)(nil)

// NewFake returns an empty in-memory KeyStore.
func NewFake() *Fake {
	return &Fake{keys: make(map[Key][]byte)}
}

// Store persists a copy of wrappedDEK for key. The copy means a caller
// mutating its slice afterward cannot alter stored state.
func (f *Fake) Store(_ context.Context, key Key, wrappedDEK []byte) error {
	if !key.complete() {
		return ErrIncompleteKey
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys[key] = slices.Clone(wrappedDEK)
	return nil
}

// Fetch returns a copy of the wrapped DEK for key, or a clean miss if absent.
func (f *Fake) Fetch(_ context.Context, key Key) ([]byte, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	wrapped, ok := f.keys[key]
	if !ok {
		return nil, false, nil
	}
	return slices.Clone(wrapped), true, nil
}

// Shred deletes every key for the given records within tenantID and returns
// the count removed. A record id with no stored keys contributes nothing;
// shredding an already-erased record is therefore harmless and idempotent.
func (f *Fake) Shred(_ context.Context, tenantID string, recordIDs []string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	deleted := 0
	for k := range f.keys {
		if k.TenantID == tenantID && slices.Contains(recordIDs, k.RecordID) {
			delete(f.keys, k)
			deleted++
		}
	}
	return deleted, nil
}
