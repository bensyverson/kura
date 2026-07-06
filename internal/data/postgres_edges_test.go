package data

import (
	"context"
	"errors"
	"testing"
)

// The Postgres store satisfies the same happy-path edge contract the fake
// does: edges supplied at creation are persisted in the record's transaction,
// queryable by target (ordered by source seq via a join to kura.records) and
// by source.
func TestPostgresStoreEdgesHappyPath(t *testing.T) {
	env := newDataTestEnv(t)
	ce := newCryptoEnv(t)
	tenant := newTenantID(t, env)
	store := newRecordStore(t, connectAsAPIRole(t, env), tenant, ce)
	assertEdgeHappyPath(t, store, store)
}

// An edge to a target record that does not exist is rejected via the foreign
// key as ErrEdgeTargetNotFound, and the whole insert rolls back — the record
// it was attached to is not stored.
func TestPostgresStoreInsertEdgeToMissingTargetIsRejected(t *testing.T) {
	ctx := context.Background()
	env := newDataTestEnv(t)
	ce := newCryptoEnv(t)
	tenant := newTenantID(t, env)
	store := newRecordStore(t, connectAsAPIRole(t, env), tenant, ce)

	// A syntactically valid uuid that was never inserted.
	const missing = "00000000-0000-0000-0000-000000000000"
	_, err := store.Insert(ctx, RecordInput{
		Entity:        "event",
		Fields:        []FieldInput{{Name: "label", Type: "string", Value: "orphan"}},
		Relationships: []EdgeInput{{Relationship: "about", TargetID: missing}},
	})
	if !errors.Is(err, ErrEdgeTargetNotFound) {
		t.Fatalf("Insert with a missing edge target = %v, want ErrEdgeTargetNotFound", err)
	}
	if n, _ := store.Count(ctx, "event"); n != 0 {
		t.Errorf("event record stored despite a rejected edge (count=%d); insert must roll back", n)
	}
}

// Edges are tenant-isolated by row-level security: a store scoped to another
// tenant cannot see them, even sharing the same pool and table.
func TestPostgresStoreEdgesAreTenantIsolated(t *testing.T) {
	ctx := context.Background()
	env := newDataTestEnv(t)
	pool := connectAsAPIRole(t, env)
	ce := newCryptoEnv(t)
	tenantA := newTenantID(t, env)
	tenantB := newTenantID(t, env)
	storeA := newRecordStore(t, pool, tenantA, ce)
	storeB := newRecordStore(t, pool, tenantB, ce)

	subject, err := storeA.Insert(ctx, RecordInput{
		Entity: "subject",
		Fields: []FieldInput{{Name: "name", Type: "string", Value: "X"}},
	})
	if err != nil {
		t.Fatalf("insert subject: %v", err)
	}
	if _, err := storeA.Insert(ctx, RecordInput{
		Entity:        "event",
		Fields:        []FieldInput{{Name: "label", Type: "string", Value: "e"}},
		Relationships: []EdgeInput{{Relationship: "about", TargetID: subject}},
	}); err != nil {
		t.Fatalf("insert event: %v", err)
	}

	// Tenant A sees its edge.
	if edges, err := storeA.EdgesByTarget(ctx, subject); err != nil || len(edges) != 1 {
		t.Fatalf("tenant A EdgesByTarget = %d edges, err %v; want 1", len(edges), err)
	}
	// Tenant B sees nothing.
	if edges, err := storeB.EdgesByTarget(ctx, subject); err != nil || len(edges) != 0 {
		t.Errorf("tenant B EdgesByTarget = %d edges, err %v; want 0 (RLS isolation)", len(edges), err)
	}
}

// PostgresStore satisfies the EdgeReader interface.
func TestPostgresStoreIsAnEdgeReader(t *testing.T) {
	var _ EdgeReader = (*PostgresStore)(nil)
}
