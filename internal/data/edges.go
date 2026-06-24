package data

import (
	"context"
	"errors"
)

// ErrEdgeTargetNotFound is returned when a relationship edge names a target
// record that does not exist. In Postgres it surfaces a foreign-key
// violation; the in-memory fake raises the same sentinel, so both stores
// guarantee an edge can never dangle.
var ErrEdgeTargetNotFound = errors.New("data: relationship edge target record not found")

// EdgeInput is one relationship edge supplied when a record is created: the
// relationship name (as declared on the source entity in the manifest) and
// the id of the target record it points at. The source is the record being
// created, so it is not named here.
//
// Edges are carried on RecordInput and persisted by the RecordWriter in the
// SAME tenant-scoped transaction as the record — a record and its edges
// commit together or not at all, so an edge can never reference a record
// that failed to write.
//
// Supplying edges only at creation is deliberate: standalone post-creation
// add/remove/replace of edges is a mutation, and Kura has no update path
// yet, so it rides with that future work (see
// project/2026-06-24-relationships.md).
type EdgeInput struct {
	Relationship string
	TargetID     string
}

// Edge is one persisted relationship edge between two records, as read back.
//
// SourceSeq is the source record's order key — its value from the shared
// record sequence (migration 0007) — carried so callers can order "edges
// pointing at a target" by it (e.g. all of a subject's referencing records,
// in order) without a second round-trip. It is populated from a join to
// kura.records, never stored on the edge row.
type Edge struct {
	Relationship string
	SourceID     string
	SourceSeq    int64
	TargetID     string
}

// EdgeReader reads relationship edges. It is the read seam for edges,
// alongside the RecordStore and enforcement-blind in the same way: it
// returns raw edges and leaves authorization to the gate. Both reads are
// tenant-scoped by the same row-level security the RecordStore relies on.
type EdgeReader interface {
	// EdgesByTarget returns every edge whose target is targetID, ordered by
	// the source record's sequence, so a subject's referencing records read
	// back in deterministic, clock-skew-immune order.
	EdgesByTarget(ctx context.Context, targetID string) ([]Edge, error)
	// EdgesBySource returns every edge originating from sourceID.
	EdgesBySource(ctx context.Context, sourceID string) ([]Edge, error)
}
