package data

import (
	"context"
	"testing"
)

func seeded() *MemStore {
	s := NewMemStore()
	s.Put("patient", Record{ID: "p1", Fields: map[string]string{"full_name": "Jane Doe", "account": "ACCT-1"}})
	s.Put("patient", Record{ID: "p2", Fields: map[string]string{"full_name": "John Roe", "account": "ACCT-2"}})
	s.Put("patient", Record{ID: "p3", Fields: map[string]string{"full_name": "Sam Poe", "account": "ACCT-3"}})
	s.Put("doctor", Record{ID: "d1", Fields: map[string]string{"name": "Dr. Who"}})
	return s
}

func TestMemStoreGetReturnsStoredRecord(t *testing.T) {
	s := seeded()
	rec, ok, err := s.Get(context.Background(), "patient", "p2")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("Get: record not found, want found")
	}
	if rec.ID != "p2" || rec.Fields["full_name"] != "John Roe" {
		t.Errorf("Get returned %+v, want p2 / John Roe", rec)
	}
}

// A Get for an id that does not exist is not an error — it is a
// not-found, reported through the ok return so the caller can map it to
// a 404 rather than a 500.
func TestMemStoreGetMissingRecordIsNotAnError(t *testing.T) {
	s := seeded()
	if _, ok, err := s.Get(context.Background(), "patient", "nope"); err != nil || ok {
		t.Errorf("Get(missing) = ok %v, err %v; want ok false, err nil", ok, err)
	}
	// An unknown entity is likewise a not-found, not an error.
	if _, ok, err := s.Get(context.Background(), "ghost", "p1"); err != nil || ok {
		t.Errorf("Get(unknown entity) = ok %v, err %v; want ok false, err nil", ok, err)
	}
}

// The fields a Get returns are a copy: mutating them must not corrupt
// the stored record.
func TestMemStoreGetReturnsACopy(t *testing.T) {
	s := seeded()
	rec, _, _ := s.Get(context.Background(), "patient", "p1")
	rec.Fields["full_name"] = "TAMPERED"

	again, _, _ := s.Get(context.Background(), "patient", "p1")
	if again.Fields["full_name"] != "Jane Doe" {
		t.Errorf("stored record was mutated through a returned copy: %q", again.Fields["full_name"])
	}
}

// List returns an entity's records in a stable order, so pagination
// over it is well-defined.
func TestMemStoreListIsOrderedAndComplete(t *testing.T) {
	s := seeded()
	recs, err := s.List(context.Background(), "patient", 100, 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("got %d patients, want 3", len(recs))
	}
	for i, want := range []string{"p1", "p2", "p3"} {
		if recs[i].ID != want {
			t.Errorf("record %d = %q, want %q (List must be stably ordered)", i, recs[i].ID, want)
		}
	}
}

// List honors limit and offset — the primitive the gate's bounded
// pagination sits on top of.
func TestMemStoreListPaginates(t *testing.T) {
	s := seeded()
	recs, err := s.List(context.Background(), "patient", 2, 1)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(recs) != 2 || recs[0].ID != "p2" || recs[1].ID != "p3" {
		t.Errorf("List(limit 2, offset 1) = %+v, want p2,p3", recs)
	}
	// An offset past the end is an empty page, not an error.
	past, err := s.List(context.Background(), "patient", 10, 99)
	if err != nil || len(past) != 0 {
		t.Errorf("List past the end = %+v, err %v; want empty, nil", past, err)
	}
	// A limit that runs past the end returns what is there.
	tail, err := s.List(context.Background(), "patient", 10, 2)
	if err != nil || len(tail) != 1 || tail[0].ID != "p3" {
		t.Errorf("List(limit 10, offset 2) = %+v, err %v; want [p3], nil", tail, err)
	}
}

// Listing an entity with no records is an empty page, not an error.
func TestMemStoreListUnknownEntityIsEmpty(t *testing.T) {
	s := seeded()
	recs, err := s.List(context.Background(), "ghost", 10, 0)
	if err != nil || len(recs) != 0 {
		t.Errorf("List(unknown entity) = %+v, err %v; want empty, nil", recs, err)
	}
}

// Count reports how many records an entity holds without paging them
// into memory — the primitive the dashboard overview's totals sit on. An
// entity with no records counts zero, not an error.
func TestMemStoreCount(t *testing.T) {
	s := seeded()
	if n, err := s.Count(context.Background(), "patient"); err != nil || n != 3 {
		t.Errorf("Count(patient) = %d, err %v; want 3, nil", n, err)
	}
	if n, err := s.Count(context.Background(), "doctor"); err != nil || n != 1 {
		t.Errorf("Count(doctor) = %d, err %v; want 1, nil", n, err)
	}
	if n, err := s.Count(context.Background(), "ghost"); err != nil || n != 0 {
		t.Errorf("Count(unknown entity) = %d, err %v; want 0, nil", n, err)
	}
}

// MemStore satisfies the RecordStore interface.
func TestMemStoreIsARecordStore(t *testing.T) {
	var _ RecordStore = NewMemStore()
}
