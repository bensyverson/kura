package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeEdgesServer stands in for kura serve's edges endpoint: it records the
// direction it was asked for and returns a fixed edge.
type fakeEdgesServer struct {
	gotDirection string
}

func (f *fakeEdgesServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/{entity}/{id}/edges", func(w http.ResponseWriter, r *http.Request) {
		f.gotDirection = r.URL.Query().Get("direction")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"edges": []map[string]any{
				{"relationship": "primary_provider", "source_id": r.PathValue("id"), "source_seq": 7, "target_id": "prov-1"},
			},
		})
	})
	return mux
}

// setupEdgesCLI stands up a fake edges server and primes the token cache so
// `kura edges` can address it.
func setupEdgesCLI(t *testing.T, fake *fakeEdgesServer) string {
	t.Helper()
	srv := httptest.NewServer(fake.handler())
	t.Cleanup(srv.Close)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cache, err := defaultTokenCache()
	if err != nil {
		t.Fatalf("defaultTokenCache: %v", err)
	}
	if err := cache.save(srv.URL, "tok"); err != nil {
		t.Fatalf("cache.save: %v", err)
	}
	return srv.URL
}

// `kura edges` is wired as a real command carrying --direction.
func TestEdgesCommandIsWired(t *testing.T) {
	root := newRootCmd()
	edges, _, err := root.Find([]string{"edges"})
	if err != nil {
		t.Fatalf("finding edges command: %v", err)
	}
	if edges.Name() != "edges" {
		t.Fatalf("found command %q, want edges", edges.Name())
	}
	if edges.Flags().Lookup("direction") == nil {
		t.Fatal("edges command has no --direction flag")
	}
}

// `kura edges <entity> <id> --direction out` reads the record's edges and
// reports them, passing the direction through to the server.
func TestEdgesListsRecordEdges(t *testing.T) {
	fake := &fakeEdgesServer{}
	server := setupEdgesCLI(t, fake)

	stdout, _, err := runRoot(t, "edges", "patient", "p1", "--direction", "out", "--server", server)
	if err != nil {
		t.Fatalf("edges: %v", err)
	}
	if fake.gotDirection != "out" {
		t.Errorf("server asked for direction %q, want out", fake.gotDirection)
	}
	if !strings.Contains(stdout.String(), "primary_provider") || !strings.Contains(stdout.String(), "prov-1") {
		t.Errorf("output %q does not report the edge", stdout.String())
	}
}

// The direction is required and explicit: omitting it is a usage error, and
// the server is never called.
func TestEdgesRequiresDirection(t *testing.T) {
	fake := &fakeEdgesServer{}
	server := setupEdgesCLI(t, fake)

	if _, _, err := runRoot(t, "edges", "patient", "p1", "--server", server); err == nil {
		t.Fatal("edges with no --direction returned no error")
	}
	if fake.gotDirection != "" {
		t.Errorf("server was called (direction %q) despite a missing --direction", fake.gotDirection)
	}
}

// An invalid direction is a usage error, rejected before any server call.
func TestEdgesRejectsInvalidDirection(t *testing.T) {
	fake := &fakeEdgesServer{}
	server := setupEdgesCLI(t, fake)

	if _, _, err := runRoot(t, "edges", "patient", "p1", "--direction", "sideways", "--server", server); err == nil {
		t.Fatal("edges with an invalid --direction returned no error")
	}
	if fake.gotDirection != "" {
		t.Error("server was called despite an invalid --direction")
	}
}
