package keystore

import (
	"context"
	"slices"
	"sort"
	"sync"
)

// Fake is an in-memory KeyStore for unit tests of the write, read, erase, and
// rotation paths. It implements the identical contract to the Postgres store —
// tenant-scoped, clean misses, set-based shred, version-tracked rotation — so
// a test that passes against the Fake is exercising the same behaviour the
// production store guarantees. It is safe for concurrent use.
type Fake struct {
	mu   sync.Mutex
	keys map[Key]fakeEntry
}

// fakeEntry is one stored wrapped DEK and the KEK generation that wrapped it,
// mirroring the Postgres row's (wrapped_dek, kek_version).
type fakeEntry struct {
	wrapped []byte
	version int
}

var _ KeyStore = (*Fake)(nil)

// NewFake returns an empty in-memory KeyStore.
func NewFake() *Fake {
	return &Fake{keys: make(map[Key]fakeEntry)}
}

// Store persists a copy of wrappedDEK for key at the initial KEK version (1),
// matching the Postgres column default. The copy means a caller mutating its
// slice afterward cannot alter stored state.
func (f *Fake) Store(_ context.Context, key Key, wrappedDEK []byte) error {
	if !key.complete() {
		return ErrIncompleteKey
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys[key] = fakeEntry{wrapped: slices.Clone(wrappedDEK), version: 1}
	return nil
}

// Fetch returns a copy of the wrapped DEK for key, or a clean miss if absent.
func (f *Fake) Fetch(_ context.Context, key Key) ([]byte, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.keys[key]
	if !ok {
		return nil, false, nil
	}
	return slices.Clone(e.wrapped), true, nil
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

// RotateBatch re-wraps up to limit DEKs at fromVersion within tenantID,
// advancing them to toVersion. It selects deterministically (by record, then
// field) so batching is stable, computes every re-wrap before mutating any
// entry, and applies the batch atomically — a rewrap error advances nothing,
// mirroring the Postgres transaction.
func (f *Fake) RotateBatch(_ context.Context, tenantID string, fromVersion, toVersion, limit int, rewrap Rewrap) (int, error) {
	if toVersion <= fromVersion {
		return 0, ErrInvalidRotation
	}
	if limit < 1 {
		limit = 1
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	var pending []Key
	for k, e := range f.keys {
		if k.TenantID == tenantID && e.version == fromVersion {
			pending = append(pending, k)
		}
	}
	sort.Slice(pending, func(i, j int) bool {
		if pending[i].RecordID != pending[j].RecordID {
			return pending[i].RecordID < pending[j].RecordID
		}
		return pending[i].FieldName < pending[j].FieldName
	})
	if len(pending) > limit {
		pending = pending[:limit]
	}

	rewrapped := make([][]byte, len(pending))
	for i, k := range pending {
		nw, err := rewrap(slices.Clone(f.keys[k].wrapped))
		if err != nil {
			return 0, err
		}
		rewrapped[i] = slices.Clone(nw)
	}
	for i, k := range pending {
		f.keys[k] = fakeEntry{wrapped: rewrapped[i], version: toVersion}
	}
	return len(pending), nil
}

// Version reports the KEK generation currently wrapping key, and whether the
// key is present. It is a test accessor for asserting rotation advanced a row;
// the production KeyStore contract exposes no version — reads never need it.
func (f *Fake) Version(key Key) (int, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.keys[key]
	return e.version, ok
}
