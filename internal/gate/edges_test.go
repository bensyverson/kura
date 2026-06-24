package gate

import (
	"context"
	"errors"
	"testing"

	"github.com/bensyverson/kura/internal/audit"
)

// edgesFetcher returns a fixed pair of edges and a pointer that reports
// whether it ran, so a test can assert the gate never reaches the fetch on a
// denied or unknown-entity request.
func edgesFetcher(views ...EdgeView) (EdgesFetcher, *bool) {
	ran := false
	f := func(_ context.Context) ([]EdgeView, error) {
		ran = true
		return views, nil
	}
	return f, &ran
}

// Edges runs the full read chain for an authorized reader: it returns the
// fetched edges and audits authentication -> authorization -> access.
func TestEdgesRunsChainForAuthorizedReader(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "alice", "admin")
	fetch, ran := edgesFetcher(
		EdgeView{Relationship: "about", SourceID: "evt-1", SourceSeq: 1, TargetID: "subj-1"},
		EdgeView{Relationship: "about", SourceID: "evt-2", SourceSeq: 2, TargetID: "subj-1"},
	)

	res, err := h.gate.Edges(context.Background(), EdgesRequest{
		Token:      tok,
		Entity:     "patient",
		ResourceID: "subj-1",
	}, fetch)
	if err != nil {
		t.Fatalf("Edges: %v", err)
	}
	if !*ran {
		t.Error("fetcher was never called")
	}
	if len(res.Edges) != 2 || res.Edges[0].SourceID != "evt-1" || res.Edges[1].SourceSeq != 2 {
		t.Errorf("edges = %+v, want the two fetched edges in order", res.Edges)
	}
	if res.Principal.ID != "alice" {
		t.Errorf("Principal.ID = %q, want alice", res.Principal.ID)
	}
	kinds := eventKinds(t, h.store)
	want := []audit.Kind{audit.KindAuthentication, audit.KindAuthorization, audit.KindAccess}
	if len(kinds) != 3 || kinds[0] != want[0] || kinds[1] != want[1] || kinds[2] != want[2] {
		t.Errorf("audit kinds = %v, want %v", kinds, want)
	}
}

// A principal whose role cannot read is denied: Edges returns ErrDenied and
// the fetcher is never reached.
func TestEdgesDeniesReaderWithoutReadGrant(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "ron") // no roles: no read grant
	fetch, ran := edgesFetcher()

	_, err := h.gate.Edges(context.Background(), EdgesRequest{
		Token:      tok,
		Entity:     "patient",
		ResourceID: "subj-1",
	}, fetch)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("Edges err = %v, want ErrDenied", err)
	}
	if *ran {
		t.Error("fetcher was reached for a denied request")
	}
}

// An unknown entity is refused before any fetch.
func TestEdgesRejectsUnknownEntity(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "alice", "admin")
	fetch, ran := edgesFetcher()

	_, err := h.gate.Edges(context.Background(), EdgesRequest{
		Token:      tok,
		Entity:     "ghost",
		ResourceID: "subj-1",
	}, fetch)
	if !errors.Is(err, ErrUnknownEntity) {
		t.Fatalf("Edges err = %v, want ErrUnknownEntity", err)
	}
	if *ran {
		t.Error("fetcher was reached for an unknown entity")
	}
}
