package keystore_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/bensyverson/kura/internal/keystore"
)

// countingStore wraps a Fake and counts Fetch calls, so a cache hit can be
// distinguished from a key-store round-trip.
type countingStore struct {
	*keystore.Fake
	fetches int
}

func (c *countingStore) Fetch(ctx context.Context, k keystore.Key) ([]byte, bool, error) {
	c.fetches++
	return c.Fake.Fetch(ctx, k)
}

// countingUnwrapper is an identity unwrapper that counts how often it runs,
// so a cache hit (no unwrap) is distinguishable from a miss (one unwrap).
type countingUnwrapper struct {
	calls int
	err   error
}

func (u *countingUnwrapper) Unwrap(wrapped []byte) ([]byte, error) {
	u.calls++
	if u.err != nil {
		return nil, u.err
	}
	// Prefix so the "unwrapped" bytes differ from the wrapped input, proving
	// the cache returns the unwrapped form.
	return append([]byte("dek:"), wrapped...), nil
}

func newCacheEnv(t *testing.T, capacity int) (*countingStore, *countingUnwrapper, *keystore.Cache) {
	t.Helper()
	store := &countingStore{Fake: keystore.NewFake()}
	unwrap := &countingUnwrapper{}
	return store, unwrap, keystore.NewCache(store, unwrap, capacity)
}

func TestCacheHitAvoidsStoreAndUnwrap(t *testing.T) {
	ctx := context.Background()
	store, unwrap, cache := newCacheEnv(t, 8)
	k := key("t1", "r1", "email")
	must(t, store.Store(ctx, k, []byte("wrapped")))

	first, found, err := cache.Unwrapped(ctx, k)
	if err != nil || !found {
		t.Fatalf("first Unwrapped: found=%v err=%v", found, err)
	}
	if want := []byte("dek:wrapped"); !bytes.Equal(first, want) {
		t.Fatalf("Unwrapped = %q, want %q", first, want)
	}
	if store.fetches != 1 || unwrap.calls != 1 {
		t.Fatalf("after miss: fetches=%d unwraps=%d, want 1/1", store.fetches, unwrap.calls)
	}

	if _, _, err := cache.Unwrapped(ctx, k); err != nil {
		t.Fatalf("second Unwrapped: %v", err)
	}
	if store.fetches != 1 || unwrap.calls != 1 {
		t.Fatalf("cache hit did extra work: fetches=%d unwraps=%d, want 1/1", store.fetches, unwrap.calls)
	}
}

func TestCacheMissOnAbsentKey(t *testing.T) {
	ctx := context.Background()
	_, _, cache := newCacheEnv(t, 8)
	dek, found, err := cache.Unwrapped(ctx, key("t1", "gone", "email"))
	if err != nil {
		t.Fatalf("Unwrapped of absent key: %v", err)
	}
	if found || dek != nil {
		t.Fatalf("absent key Unwrapped = %q found=%v, want nil/false", dek, found)
	}
}

func TestCacheShredInvalidatesAndDelegates(t *testing.T) {
	ctx := context.Background()
	store, _, cache := newCacheEnv(t, 8)
	k := key("t1", "r1", "email")
	must(t, store.Store(ctx, k, []byte("wrapped")))

	// Warm the cache so the DEK is hot before erasure.
	if _, found, _ := cache.Unwrapped(ctx, k); !found {
		t.Fatal("expected to warm the cache")
	}

	deleted, err := cache.Shred(ctx, "t1", []string{"r1"})
	if err != nil {
		t.Fatalf("Shred: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("Shred deleted = %d, want 1 (delegated to store)", deleted)
	}
	// The underlying store no longer holds the key...
	if _, found, _ := store.Fetch(ctx, k); found {
		t.Fatal("store still holds the DEK after cache.Shred")
	}
	// ...and a post-shred read must NOT be served from the stale cache.
	if _, found, _ := cache.Unwrapped(ctx, k); found {
		t.Fatal("erased DEK was served from a stale cache entry")
	}
}

func TestCacheEvictsLeastRecentlyUsed(t *testing.T) {
	ctx := context.Background()
	store, _, cache := newCacheEnv(t, 2)
	a, b, c := key("t1", "a", "f"), key("t1", "b", "f"), key("t1", "c", "f")
	for _, k := range []keystore.Key{a, b, c} {
		must(t, store.Store(ctx, k, []byte("w")))
	}

	mustGet := func(k keystore.Key) {
		if _, found, err := cache.Unwrapped(ctx, k); err != nil || !found {
			t.Fatalf("Unwrapped(%v): found=%v err=%v", k, found, err)
		}
	}
	mustGet(a) // cache: [a]
	mustGet(b) // cache: [b,a]
	mustGet(a) // touch a so b is now least-recently-used: [a,b]
	fetchesBefore := store.fetches
	mustGet(c) // inserts c, must evict b: [c,a]

	// a and c are hits (no new fetch); b was evicted (forces a fetch).
	mustGet(a)
	mustGet(c)
	if store.fetches != fetchesBefore+1 {
		t.Fatalf("a/c should be cached: fetches=%d, want %d", store.fetches, fetchesBefore+1)
	}
	mustGet(b) // evicted → must re-fetch
	if store.fetches != fetchesBefore+2 {
		t.Fatalf("b should have been evicted (LRU): fetches=%d, want %d", store.fetches, fetchesBefore+2)
	}
}

func TestCacheUnwrapFailureSurfacesAsError(t *testing.T) {
	ctx := context.Background()
	store := &countingStore{Fake: keystore.NewFake()}
	boom := errors.New("unwrap boom")
	cache := keystore.NewCache(store, &countingUnwrapper{err: boom}, 8)
	k := key("t1", "r1", "email")
	must(t, store.Store(ctx, k, []byte("wrapped")))

	_, found, err := cache.Unwrapped(ctx, k)
	if !errors.Is(err, boom) {
		t.Fatalf("Unwrapped err = %v, want unwrap boom", err)
	}
	if found {
		t.Fatal("a genuine unwrap failure must not report found=true")
	}
}

func TestCacheReturnsCopy(t *testing.T) {
	ctx := context.Background()
	store, _, cache := newCacheEnv(t, 8)
	k := key("t1", "r1", "email")
	must(t, store.Store(ctx, k, []byte("wrapped")))

	got, _, _ := cache.Unwrapped(ctx, k)
	got[0] = 'X' // mutating the caller's copy must not poison the cache
	again, _, _ := cache.Unwrapped(ctx, k)
	if !bytes.Equal(again, []byte("dek:wrapped")) {
		t.Fatalf("cache entry mutated via returned slice: got %q", again)
	}
}
