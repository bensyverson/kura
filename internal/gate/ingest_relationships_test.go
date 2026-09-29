package gate

import (
	"context"
	"errors"
	"testing"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/cedar"
	"github.com/bensyverson/kura/internal/identity"
	"github.com/bensyverson/kura/internal/manifest"
	"github.com/bensyverson/kura/internal/pii"
)

// relationshipManifest declares a "patient" that relates to "provider" two
// ways: a one-cardinality primary_provider and a many-cardinality care_team.
// It exercises every instance-level relationship check the gate makes —
// declared, cardinality, target existence, and target entity.
func relationshipManifest() *manifest.Manifest {
	return &manifest.Manifest{
		Version: "1",
		Entities: []manifest.Entity{
			{
				Name:   "provider",
				Fields: []manifest.Field{{Name: "name", Type: manifest.FieldString}},
			},
			{
				Name:   "patient",
				Fields: []manifest.Field{{Name: "full_name", Type: manifest.FieldString}},
				Relationships: []manifest.Relationship{
					{Name: "primary_provider", Kind: manifest.RelationshipOne, Target: "provider"},
					{Name: "care_team", Kind: manifest.RelationshipMany, Target: "provider"},
				},
			},
		},
	}
}

// newRelationshipHarness builds a gate over relationshipManifest. No detector
// registrations are needed — these tests are about relationships, not PII.
func newRelationshipHarness(t *testing.T) *harness {
	t.Helper()
	m := relationshipManifest()
	evaluator, err := cedar.NewEvaluator(cedar.DefaultPolicy(m))
	if err != nil {
		t.Fatalf("building evaluator: %v", err)
	}
	auth := identity.NewAuthenticator([]byte("test-signing-secret"))
	roles := NewMapRoleResolver()
	store := audit.NewMemStore()
	g, err := New(auth, evaluator, roles, m, pii.NewScanner(pii.NewFakeDetector()), audit.NewRecorder(store))
	if err != nil {
		t.Fatalf("New gate: %v", err)
	}
	return &harness{gate: g, auth: auth, roles: roles, store: store, detector: nil}
}

// edgesFor collects a captured record's edges for one relationship, in order.
func edgesFor(rec *WriteRecord, relationship string) []string {
	var ids []string
	for _, e := range rec.Relationships {
		if e.Relationship == relationship {
			ids = append(ids, e.TargetID)
		}
	}
	return ids
}

// A relationship the manifest does not declare for the entity is refused
// before any write, the same way an undeclared field is.
func TestIngestRejectsUndeclaredRelationship(t *testing.T) {
	h := newRelationshipHarness(t)
	tok := h.token(t, "alice", "admin")
	write, got := captureWriter("rec-1")
	exists := existsSet([2]string{"provider", "prov-1"})

	_, err := h.gate.Ingest(context.Background(), IngestRequest{
		Token:         tok,
		Entity:        "patient",
		Fields:        map[string]string{"full_name": "Jane Doe"},
		Relationships: map[string][]string{"not_a_relationship": {"prov-1"}},
	}, exists, write)
	if !errors.Is(err, ErrUnknownRelationship) {
		t.Fatalf("Ingest err = %v, want ErrUnknownRelationship", err)
	}
	if *got != nil {
		t.Error("writer was reached for an undeclared relationship")
	}
}

// A relationship whose target record does not exist is refused before any
// write.
func TestIngestRejectsMissingRelationshipTarget(t *testing.T) {
	h := newRelationshipHarness(t)
	tok := h.token(t, "alice", "admin")
	write, got := captureWriter("rec-1")
	exists := existsSet() // no records exist

	_, err := h.gate.Ingest(context.Background(), IngestRequest{
		Token:         tok,
		Entity:        "patient",
		Fields:        map[string]string{"full_name": "Jane Doe"},
		Relationships: map[string][]string{"primary_provider": {"ghost"}},
	}, exists, write)
	if !errors.Is(err, ErrEdgeTarget) {
		t.Fatalf("Ingest err = %v, want ErrEdgeTarget", err)
	}
	if *got != nil {
		t.Error("writer was reached for a missing relationship target")
	}
}

// A target that exists but under a different entity than the relationship
// declares is refused — the existence check is keyed on the declared entity,
// so a wrong-entity target is simply absent.
func TestIngestRejectsWrongEntityRelationshipTarget(t *testing.T) {
	h := newRelationshipHarness(t)
	tok := h.token(t, "alice", "admin")
	write, got := captureWriter("rec-1")
	// "pat-9" exists, but as a patient — not the provider the relationship wants.
	exists := existsSet([2]string{"patient", "pat-9"})

	_, err := h.gate.Ingest(context.Background(), IngestRequest{
		Token:         tok,
		Entity:        "patient",
		Fields:        map[string]string{"full_name": "Jane Doe"},
		Relationships: map[string][]string{"primary_provider": {"pat-9"}},
	}, exists, write)
	if !errors.Is(err, ErrEdgeTarget) {
		t.Fatalf("Ingest err = %v, want ErrEdgeTarget", err)
	}
	if *got != nil {
		t.Error("writer was reached for a wrong-entity relationship target")
	}
}

// A second target on a one-cardinality relationship is refused; the writer is
// never reached.
func TestIngestRejectsSecondTargetOnOneRelationship(t *testing.T) {
	h := newRelationshipHarness(t)
	tok := h.token(t, "alice", "admin")
	write, got := captureWriter("rec-1")
	exists := existsSet([2]string{"provider", "prov-1"}, [2]string{"provider", "prov-2"})

	_, err := h.gate.Ingest(context.Background(), IngestRequest{
		Token:         tok,
		Entity:        "patient",
		Fields:        map[string]string{"full_name": "Jane Doe"},
		Relationships: map[string][]string{"primary_provider": {"prov-1", "prov-2"}},
	}, exists, write)
	if !errors.Is(err, ErrCardinality) {
		t.Fatalf("Ingest err = %v, want ErrCardinality", err)
	}
	if *got != nil {
		t.Error("writer was reached for a one-relationship with two targets")
	}
}

// A many-cardinality relationship accepts multiple targets, and every edge is
// carried to the writer.
func TestIngestAcceptsMultipleTargetsOnManyRelationship(t *testing.T) {
	h := newRelationshipHarness(t)
	tok := h.token(t, "alice", "admin")
	write, got := captureWriter("rec-1")
	exists := existsSet([2]string{"provider", "prov-1"}, [2]string{"provider", "prov-2"})

	_, err := h.gate.Ingest(context.Background(), IngestRequest{
		Token:         tok,
		Entity:        "patient",
		Fields:        map[string]string{"full_name": "Jane Doe"},
		Relationships: map[string][]string{"care_team": {"prov-1", "prov-2"}},
	}, exists, write)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if *got == nil {
		t.Fatal("writer was never called")
	}
	ids := edgesFor(*got, "care_team")
	if len(ids) != 2 {
		t.Fatalf("care_team edges = %v, want two", ids)
	}
}

// Validated edges are carried to the writer with the record, and the create
// is authorized and audited — the relationship rides on ActionCreate of the
// source entity, with no separate action.
func TestIngestPersistsValidatedEdges(t *testing.T) {
	h := newRelationshipHarness(t)
	tok := h.token(t, "alice", "admin")
	write, got := captureWriter("rec-1")
	exists := existsSet([2]string{"provider", "prov-1"})

	_, err := h.gate.Ingest(context.Background(), IngestRequest{
		Token:         tok,
		Entity:        "patient",
		Fields:        map[string]string{"full_name": "Jane Doe"},
		Relationships: map[string][]string{"primary_provider": {"prov-1"}},
	}, exists, write)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if *got == nil {
		t.Fatal("writer was never called")
	}
	if ids := edgesFor(*got, "primary_provider"); len(ids) != 1 || ids[0] != "prov-1" {
		t.Fatalf("primary_provider edges = %v, want [prov-1]", ids)
	}
	kinds := eventKinds(t, h.store)
	want := []audit.Kind{audit.KindAuthentication, audit.KindAuthorization, audit.KindAccess}
	if len(kinds) != 3 || kinds[2] != want[2] {
		t.Errorf("audit kinds = %v, want create access audited", kinds)
	}
}
