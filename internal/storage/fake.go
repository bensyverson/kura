package storage

import (
	"context"
	"sort"
	"strings"
	"sync"
)

// Fake is an in-memory Store for tests and for break-glass paths that run
// before the real DO Spaces store is reachable. It enforces the same
// role semantics as the production deny-delete posture: under AppendOnly
// it refuses overwrite and delete, so a test exercising the runtime
// writer cannot accidentally destroy data the real bucket policy would
// protect.
type Fake struct {
	spec BucketSpec
	role Role

	mu      sync.Mutex
	objects map[string][]byte
}

// NewFake returns an empty in-memory Store for spec, opened with role.
func NewFake(spec BucketSpec, role Role) *Fake {
	return &Fake{
		spec:    spec,
		role:    role,
		objects: make(map[string][]byte),
	}
}

// Spec returns the bucket's immutable description.
func (f *Fake) Spec() BucketSpec { return f.spec }

// Role returns the access level the Fake was opened with.
func (f *Fake) Role() Role { return f.role }

// Put writes data at key. Under AppendOnly, putting an existing key
// returns ErrOverwriteDenied and leaves the stored object untouched.
func (f *Fake) Put(_ context.Context, key string, data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.role == AppendOnly {
		if _, exists := f.objects[key]; exists {
			return ErrOverwriteDenied
		}
	}
	stored := make([]byte, len(data))
	copy(stored, data)
	f.objects[key] = stored
	return nil
}

// Get returns the object at key, or ErrNotFound.
func (f *Fake) Get(_ context.Context, key string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	stored, ok := f.objects[key]
	if !ok {
		return nil, ErrNotFound
	}
	out := make([]byte, len(stored))
	copy(out, stored)
	return out, nil
}

// List returns the keys with the given prefix, in lexical order.
func (f *Fake) List(_ context.Context, prefix string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	var keys []string
	for k := range f.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

// Delete removes the object at key. Under AppendOnly it returns
// ErrDeleteDenied and leaves the object in place; under ReadWrite an
// absent key returns ErrNotFound.
func (f *Fake) Delete(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.role == AppendOnly {
		return ErrDeleteDenied
	}
	if _, ok := f.objects[key]; !ok {
		return ErrNotFound
	}
	delete(f.objects, key)
	return nil
}
