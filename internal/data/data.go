// Package data is the storage seam beneath the gate. The gate's Fetcher
// and ListFetcher callbacks have to read raw records from somewhere; a
// RecordStore is that somewhere. It is deliberately narrow and
// enforcement-blind: it returns raw field values and knows nothing about
// authorization or masking — those are the gate's job, and a store that
// tried to do them would be a second, divergent enforcement point.
//
// MemStore is the in-memory implementation used by tests and by adapters
// that have no database yet. The Postgres-backed implementation over the
// kura.records tables is a separate build-plan task; it satisfies the
// same RecordStore interface, so nothing above the seam changes when it
// lands.
package data

import (
	"context"
	"errors"
	"maps"
	"sync"
)

// ErrNotFound is the sentinel a caller raises when a Get reports no such
// record (ok == false) and the surrounding operation needs that absence
// to travel as an error — the HTTP API, for instance, turns it into a
// 404. RecordStore.Get itself never returns it: a missing record is not
// a store failure, so Get reports it through its ok return.
var ErrNotFound = errors.New("data: record not found")

// Record is one stored record: its id and its raw field values. The
// values are exactly as stored — unmasked. Masking happens in the gate,
// never here.
type Record struct {
	ID     string
	Fields map[string]string
}

// clone returns a deep copy of r, so a record handed out by a store can
// be mutated by the caller without corrupting the stored copy.
func (r Record) clone() Record {
	return Record{ID: r.ID, Fields: maps.Clone(r.Fields)}
}

// RecordStore reads stored records. It is the seam the gate's data-read
// callbacks sit on: an in-memory fake for tests, a Postgres-backed
// implementation for production. Reads are the whole interface — writes
// are a separate concern with their own enforcement (ingestion-time PII
// scanning and field encryption), not something a read seam should grow.
type RecordStore interface {
	// Get returns one record by entity and id. ok is false — with a nil
	// error — when no such record exists; a missing record is a
	// not-found, not a failure.
	Get(ctx context.Context, entity, id string) (Record, bool, error)
	// List returns a bounded, stably ordered page of an entity's
	// records. limit and offset are applied as given; the gate has
	// already clamped them. An entity with no records is an empty page.
	List(ctx context.Context, entity string, limit, offset int) ([]Record, error)
}

// MemStore is an in-memory RecordStore for tests and database-less
// adapters. It preserves insertion order per entity, so List is stably
// ordered and pagination over it is well-defined.
type MemStore struct {
	mu       sync.RWMutex
	byEntity map[string][]Record
}

var _ RecordStore = (*MemStore)(nil)

// NewMemStore returns an empty MemStore.
func NewMemStore() *MemStore {
	return &MemStore{byEntity: make(map[string][]Record)}
}

// Put stores rec under entity, appending it to that entity's records. A
// record whose id already exists is replaced in place, keeping its
// position so insertion order — and thus pagination — stays stable.
func (m *MemStore) Put(entity string, rec Record) {
	m.mu.Lock()
	defer m.mu.Unlock()
	recs := m.byEntity[entity]
	for i := range recs {
		if recs[i].ID == rec.ID {
			recs[i] = rec.clone()
			return
		}
	}
	m.byEntity[entity] = append(recs, rec.clone())
}

// Get returns the record with the given id under entity.
func (m *MemStore) Get(_ context.Context, entity, id string) (Record, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, rec := range m.byEntity[entity] {
		if rec.ID == id {
			return rec.clone(), true, nil
		}
	}
	return Record{}, false, nil
}

// List returns a page of entity's records in insertion order.
func (m *MemStore) List(_ context.Context, entity string, limit, offset int) ([]Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	recs := m.byEntity[entity]
	if offset < 0 {
		offset = 0
	}
	if offset >= len(recs) {
		return nil, nil
	}
	end := offset + limit
	if limit < 0 || end > len(recs) {
		end = len(recs)
	}
	out := make([]Record, 0, end-offset)
	for _, rec := range recs[offset:end] {
		out = append(out, rec.clone())
	}
	return out, nil
}
