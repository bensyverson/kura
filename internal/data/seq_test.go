package data

import (
	"context"
	"testing"
)

// assertRecordSeqContract is the behaviour both the in-memory fake and the
// Postgres store must share: every inserted record is assigned a positive
// seq from ONE shared sequence, strictly increasing in insertion order
// across all entities, and that same seq reads back through both Get and
// List. Running it against both stores is how the fake is held to the
// production contract.
func assertRecordSeqContract(t *testing.T, w RecordWriter, s RecordStore) {
	t.Helper()
	ctx := context.Background()

	mk := func(entity, name string) string {
		t.Helper()
		id, err := w.Insert(ctx, RecordInput{
			Entity: entity,
			Fields: []FieldInput{{Name: "full_name", Type: "string", Value: name}},
		})
		if err != nil {
			t.Fatalf("Insert(%s): %v", entity, err)
		}
		return id
	}
	get := func(entity, id string) Record {
		t.Helper()
		rec, ok, err := s.Get(ctx, entity, id)
		if err != nil || !ok {
			t.Fatalf("Get(%s,%s) = ok %v, err %v", entity, id, ok, err)
		}
		return rec
	}

	// Insert across two entities to prove the sequence is global, not
	// per-entity.
	id1 := mk("patient", "A")
	id2 := mk("doctor", "B")
	id3 := mk("patient", "C")

	r1, r2, r3 := get("patient", id1), get("doctor", id2), get("patient", id3)

	if r1.Seq <= 0 {
		t.Errorf("first record seq = %d, want > 0 (server-assigned)", r1.Seq)
	}
	if !(r1.Seq < r2.Seq && r2.Seq < r3.Seq) {
		t.Errorf("seqs = %d, %d, %d; want strictly increasing across entities (one shared sequence)", r1.Seq, r2.Seq, r3.Seq)
	}

	// The seq read through List matches the seq read through Get.
	patients, err := s.List(ctx, "patient", 100, 0)
	if err != nil {
		t.Fatalf("List(patient): %v", err)
	}
	bySeq := make(map[string]int64, len(patients))
	for _, rec := range patients {
		bySeq[rec.ID] = rec.Seq
	}
	if bySeq[id1] != r1.Seq || bySeq[id3] != r3.Seq {
		t.Errorf("List seqs = {%s:%d, %s:%d}, want them to match Get (%d, %d)",
			id1, bySeq[id1], id3, bySeq[id3], r1.Seq, r3.Seq)
	}
}

// The in-memory fake assigns the same kind of monotonic, shared seq the
// production store does, so adapters and tests that run on the fake see the
// real ordering contract.
func TestMemStoreAssignsRecordSeq(t *testing.T) {
	s := NewMemStore()
	assertRecordSeqContract(t, s, s)
}

// The Postgres store surfaces the database-assigned record sequence through
// Get and List, satisfying the same contract the fake does.
func TestPostgresStoreAssignsRecordSeq(t *testing.T) {
	env := newDataTestEnv(t)
	tenant := newTenantID(t, env)
	store, err := NewPostgresStore(connectAsAPIRole(t, env), tenant, testEncKey)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	assertRecordSeqContract(t, store, store)
}
