package keystore

import (
	"container/list"
	"context"
	"slices"
	"sync"
)

// Unwrapper unwraps a wrapped DEK under the master KEK, yielding the raw DEK
// ready to decrypt a value. It is the read-side half of the KEK capability
// (the write side wraps); the cache depends only on unwrap. Sourcing the KEK
// from the secrets manager is a separate concern — the cache takes any
// implementation, so it can be unit-tested with a trivial one.
type Unwrapper interface {
	Unwrap(wrapped []byte) (dek []byte, err error)
}

// Cache is an in-process LRU of unwrapped DEKs in front of a KeyStore. A hot
// read avoids both a key-store round-trip and an unwrap, collapsing the read
// to a map hit.
//
// Correctness, not just speed: Shred both deletes from the underlying store
// and evicts the affected entries, so a value erased by crypto-shredding can
// never be decrypted from a stale cache entry. The cache is safe for
// concurrent use.
type Cache struct {
	mu       sync.Mutex
	store    KeyStore
	unwrap   Unwrapper
	capacity int
	ll       *list.List // front = most recently used
	items    map[Key]*list.Element
}

type cacheEntry struct {
	key Key
	dek []byte
}

// NewCache returns a Cache fronting store, unwrapping with unwrap, bounded to
// capacity entries. A capacity below 1 is raised to 1 so the cache always
// holds at least the most recently used DEK.
func NewCache(store KeyStore, unwrap Unwrapper, capacity int) *Cache {
	if capacity < 1 {
		capacity = 1
	}
	return &Cache{
		store:    store,
		unwrap:   unwrap,
		capacity: capacity,
		ll:       list.New(),
		items:    make(map[Key]*list.Element),
	}
}

// Unwrapped returns the ready-to-use DEK for key. On a cache hit it returns a
// copy of the cached DEK with no key-store or unwrap work. On a miss it
// fetches the wrapped DEK, unwraps it, and populates the cache. An absent key
// — never stored, or shredded — is a clean miss (nil, false, nil); a genuine
// unwrap failure (tampering / wrong KEK) is an error, never a silent miss.
func (c *Cache) Unwrapped(ctx context.Context, key Key) ([]byte, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.items[key]; ok {
		c.ll.MoveToFront(el)
		return slices.Clone(el.Value.(*cacheEntry).dek), true, nil
	}

	wrapped, found, err := c.store.Fetch(ctx, key)
	if err != nil {
		return nil, false, err
	}
	if !found {
		return nil, false, nil
	}
	dek, err := c.unwrap.Unwrap(wrapped)
	if err != nil {
		return nil, false, err
	}
	el := c.ll.PushFront(&cacheEntry{key: key, dek: slices.Clone(dek)})
	c.items[key] = el
	c.evictLocked()
	return slices.Clone(dek), true, nil
}

// Shred deletes the wrapped DEKs for the given records from the underlying
// store and evicts any cached DEKs for those records, so an erased value
// cannot be decrypted from a stale entry. Eviction happens regardless of the
// store result: a partial or failed delete must still not leave a usable DEK
// cached.
func (c *Cache) Shred(ctx context.Context, tenantID string, recordIDs []string) (int, error) {
	c.mu.Lock()
	for k, el := range c.items {
		if k.TenantID == tenantID && slices.Contains(recordIDs, k.RecordID) {
			c.removeLocked(el)
		}
	}
	c.mu.Unlock()
	return c.store.Shred(ctx, tenantID, recordIDs)
}

// evictLocked drops least-recently-used entries until the cache is within
// capacity. The caller holds c.mu.
func (c *Cache) evictLocked() {
	for c.ll.Len() > c.capacity {
		c.removeLocked(c.ll.Back())
	}
}

// removeLocked unlinks el from both the list and the index. The caller holds
// c.mu.
func (c *Cache) removeLocked(el *list.Element) {
	if el == nil {
		return
	}
	c.ll.Remove(el)
	delete(c.items, el.Value.(*cacheEntry).key)
}
