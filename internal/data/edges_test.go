package data

import (
	"context"
	"errors"
	"testing"
)

// assertEdgeHappyPath is the edge behaviour both the in-memory fake and the
// Postgres store must share: edges supplied at record creation are persisted
// with the record, queryable by target (ordered by the source record's
// sequence) and by source. Running it against both stores holds the fake to
// the production contract.
func assertEdgeHappyPath(t *testing.T, w RecordWriter, r EdgeReader) {
	t.Helper()
	ctx := context.Background()

	subjectID, err := w.Insert(ctx, RecordInput{
		Entity: "subject",
		Fields: []FieldInput{{Name: "name", Type: "string", Value: "X"}},
	})
	if err != nil {
		t.Fatalf("insert subject: %v", err)
	}

	mkEvent := func(label string) string {
		t.Helper()
		id, err := w.Insert(ctx, RecordInput{
			Entity:        "event",
			Fields:        []FieldInput{{Name: "label", Type: "string", Value: label}},
			Relationships: []EdgeInput{{Relationship: "about", TargetID: subjectID}},
		})
		if err != nil {
			t.Fatalf("insert event %s: %v", label, err)
		}
		return id
	}
	first := mkEvent("first")
	second := mkEvent("second")

	// EdgesByTarget returns both edges, ordered by the source record's seq.
	byTarget, err := r.EdgesByTarget(ctx, subjectID)
	if err != nil {
		t.Fatalf("EdgesByTarget: %v", err)
	}
	if len(byTarget) != 2 {
		t.Fatalf("EdgesByTarget returned %d edges, want 2", len(byTarget))
	}
	if byTarget[0].SourceID != first || byTarget[1].SourceID != second {
		t.Errorf("EdgesByTarget order = %s,%s; want %s,%s (ordered by source seq)",
			byTarget[0].SourceID, byTarget[1].SourceID, first, second)
	}
	if byTarget[0].SourceSeq >= byTarget[1].SourceSeq {
		t.Errorf("EdgesByTarget source seqs not strictly increasing: %d, %d",
			byTarget[0].SourceSeq, byTarget[1].SourceSeq)
	}
	for _, e := range byTarget {
		if e.Relationship != "about" || e.TargetID != subjectID {
			t.Errorf("edge = %+v, want relationship=about target=%s", e, subjectID)
		}
	}

	// EdgesBySource returns the single edge originating from one event.
	bySource, err := r.EdgesBySource(ctx, first)
	if err != nil {
		t.Fatalf("EdgesBySource: %v", err)
	}
	if len(bySource) != 1 || bySource[0].TargetID != subjectID {
		t.Errorf("EdgesBySource(%s) = %+v, want one edge to %s", first, bySource, subjectID)
	}
}

// The fake satisfies the same happy-path edge contract the production store does.
func TestMemStoreEdgesHappyPath(t *testing.T) {
	s := NewMemStore()
	assertEdgeHappyPath(t, s, s)
}

// An edge to a target that does not exist is rejected, and the record it was
// attached to is not stored — a record and its edges are atomic. This mirrors
// the Postgres FK: an edge can never dangle.
func TestMemStoreInsertEdgeToMissingTargetIsRejected(t *testing.T) {
	ctx := context.Background()
	s := NewMemStore()
	_, err := s.Insert(ctx, RecordInput{
		Entity:        "event",
		Fields:        []FieldInput{{Name: "label", Type: "string", Value: "orphan"}},
		Relationships: []EdgeInput{{Relationship: "about", TargetID: "no-such-record"}},
	})
	if !errors.Is(err, ErrEdgeTargetNotFound) {
		t.Fatalf("Insert with a missing edge target = %v, want ErrEdgeTargetNotFound", err)
	}
	if n, _ := s.Count(ctx, "event"); n != 0 {
		t.Errorf("event record stored despite a rejected edge (count=%d); insert must be atomic", n)
	}
}

// MemStore satisfies the EdgeReader interface.
func TestMemStoreIsAnEdgeReader(t *testing.T) {
	var _ EdgeReader = NewMemStore()
}
