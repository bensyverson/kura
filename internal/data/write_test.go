package data

import (
	"context"
	"testing"
)

// MemStore satisfies the RecordWriter interface.
func TestMemStoreIsARecordWriter(t *testing.T) {
	var _ RecordWriter = (*MemStore)(nil)
}

// A record inserted through the write seam is immediately readable through
// the read seam: Insert returns an id, and Get/Count reflect the record.
// The in-memory store is the dev/test stand-in for the dashboard's data
// browser, so a write must show up as a read.
func TestMemStoreInsertIsReadable(t *testing.T) {
	s := NewMemStore()
	id, err := s.Insert(context.Background(), RecordInput{
		Entity: "patient",
		Fields: []FieldInput{
			{Name: "full_name", Type: "string", Value: "Jane Doe"},
			{Name: "ssn", Type: "string", Value: "123-45-6789", Encrypted: true},
		},
	})
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if id == "" {
		t.Fatal("Insert returned an empty id")
	}
	rec, ok, err := s.Get(context.Background(), "patient", id)
	if err != nil || !ok {
		t.Fatalf("Get after Insert: ok=%v err=%v", ok, err)
	}
	if rec.ID != id {
		t.Errorf("rec.ID = %q, want %q", rec.ID, id)
	}
	if rec.Fields["full_name"] != "Jane Doe" || rec.Fields["ssn"] != "123-45-6789" {
		t.Errorf("rec.Fields = %+v, want full_name + ssn round-tripped", rec.Fields)
	}
	n, err := s.Count(context.Background(), "patient")
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n != 1 {
		t.Errorf("Count = %d, want 1", n)
	}
}

// Each Insert mints a fresh id, so two records under the same entity are
// distinct and independently addressable.
func TestMemStoreInsertGeneratesUniqueIDs(t *testing.T) {
	s := NewMemStore()
	ctx := context.Background()
	id1, err := s.Insert(ctx, RecordInput{Entity: "e", Fields: []FieldInput{{Name: "a", Type: "string", Value: "1"}}})
	if err != nil {
		t.Fatalf("Insert 1: %v", err)
	}
	id2, err := s.Insert(ctx, RecordInput{Entity: "e", Fields: []FieldInput{{Name: "a", Type: "string", Value: "2"}}})
	if err != nil {
		t.Fatalf("Insert 2: %v", err)
	}
	if id1 == "" || id2 == "" {
		t.Fatalf("empty id: id1=%q id2=%q", id1, id2)
	}
	if id1 == id2 {
		t.Errorf("Insert reused id %q for two records", id1)
	}
}
