package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeIngestServer stands in for kura serve's ingestion endpoint: it
// accepts POST /api/{entity}, records the body, and returns a fresh id.
type fakeIngestServer struct {
	mu         sync.Mutex
	posted     []ingestCall
	nextID     int
	failStatus int // when non-zero, every POST returns this status
}

type ingestCall struct {
	entity        string
	fields        map[string]string
	relationships map[string][]string
}

func (f *fakeIngestServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/{entity}", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var rec struct {
			Fields        map[string]string   `json:"fields"`
			Relationships map[string][]string `json:"relationships"`
		}
		_ = json.Unmarshal(body, &rec)
		f.mu.Lock()
		f.posted = append(f.posted, ingestCall{entity: r.PathValue("entity"), fields: rec.Fields, relationships: rec.Relationships})
		f.nextID++
		id := f.nextID
		fail := f.failStatus
		f.mu.Unlock()
		if fail != 0 {
			http.Error(w, "rejected", fail)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "rec-" + strconv.Itoa(id)})
	})
	return mux
}

func (f *fakeIngestServer) calls() []ingestCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ingestCall(nil), f.posted...)
}

// setupIngestCLI stands up a fake ingestion server and primes the token
// cache so `kura ingest` can address it.
func setupIngestCLI(t *testing.T, fake *fakeIngestServer) string {
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

// runRootStdin is runRoot with a stdin body, for the piped-input path.
func runRootStdin(t *testing.T, stdin string, args ...string) (stdout, stderr bytes.Buffer, err error) {
	t.Helper()
	root := newRootCmd()
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetIn(strings.NewReader(stdin))
	root.SetArgs(args)
	err = root.Execute()
	return
}

func writeJSONFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "records.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing records file: %v", err)
	}
	return path
}

// `kura ingest` is wired as a real command carrying --file, not the
// not-implemented stub.
func TestIngestCommandIsWired(t *testing.T) {
	root := newRootCmd()
	ingest, _, err := root.Find([]string{"ingest"})
	if err != nil {
		t.Fatalf("finding ingest command: %v", err)
	}
	if ingest.Name() != "ingest" {
		t.Fatalf("found command %q, want ingest", ingest.Name())
	}
	if ingest.Flags().Lookup("file") == nil {
		t.Fatal("ingest command has no --file flag")
	}
}

// An array of records in a file fans out to one POST per record, each to
// the named entity's route, and the created ids are reported.
func TestIngestSendsRecordArrayAndReportsIDs(t *testing.T) {
	fake := &fakeIngestServer{}
	server := setupIngestCLI(t, fake)
	file := writeJSONFile(t, `[{"fields":{"full_name":"Jane Doe"}},{"fields":{"full_name":"John Roe"}}]`)

	stdout, _, err := runRoot(t, "ingest", "patient", "--file", file, "--server", server)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	calls := fake.calls()
	if len(calls) != 2 {
		t.Fatalf("server received %d POSTs, want 2", len(calls))
	}
	for _, c := range calls {
		if c.entity != "patient" {
			t.Errorf("POST to entity %q, want patient", c.entity)
		}
	}
	if calls[0].fields["full_name"] != "Jane Doe" || calls[1].fields["full_name"] != "John Roe" {
		t.Errorf("posted fields = %+v, want Jane Doe then John Roe", calls)
	}
	if !strings.Contains(stdout.String(), "rec-1") || !strings.Contains(stdout.String(), "rec-2") {
		t.Errorf("output %q does not report the created ids", stdout.String())
	}
}

// A single JSON object (not an array) ingests one record.
func TestIngestSendsSingleObject(t *testing.T) {
	fake := &fakeIngestServer{}
	server := setupIngestCLI(t, fake)
	file := writeJSONFile(t, `{"fields":{"full_name":"Solo"}}`)

	if _, _, err := runRoot(t, "ingest", "patient", "--file", file, "--server", server); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if calls := fake.calls(); len(calls) != 1 || calls[0].fields["full_name"] != "Solo" {
		t.Fatalf("server received %+v, want one Solo record", calls)
	}
}

// Relationships supplied on a record are sent to the server alongside the
// fields — the create-with-relationships path through the CLI.
func TestIngestSendsRelationships(t *testing.T) {
	fake := &fakeIngestServer{}
	server := setupIngestCLI(t, fake)
	file := writeJSONFile(t, `{"fields":{"full_name":"Jane"},"relationships":{"primary_provider":["prov-1"],"care_team":["a","b"]}}`)

	if _, _, err := runRoot(t, "ingest", "patient", "--file", file, "--server", server); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	calls := fake.calls()
	if len(calls) != 1 {
		t.Fatalf("server received %d POSTs, want 1", len(calls))
	}
	rels := calls[0].relationships
	if len(rels["primary_provider"]) != 1 || rels["primary_provider"][0] != "prov-1" {
		t.Errorf("primary_provider = %v, want [prov-1]", rels["primary_provider"])
	}
	if len(rels["care_team"]) != 2 || rels["care_team"][0] != "a" || rels["care_team"][1] != "b" {
		t.Errorf("care_team = %v, want [a b]", rels["care_team"])
	}
}

// With no --file, records are read from stdin.
func TestIngestReadsStdin(t *testing.T) {
	fake := &fakeIngestServer{}
	server := setupIngestCLI(t, fake)

	if _, _, err := runRootStdin(t, `{"fields":{"full_name":"Piped"}}`, "ingest", "patient", "--server", server); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if calls := fake.calls(); len(calls) != 1 || calls[0].fields["full_name"] != "Piped" {
		t.Fatalf("server received %+v, want one Piped record from stdin", calls)
	}
}

// Missing the entity argument is a usage error.
func TestIngestRequiresEntity(t *testing.T) {
	fake := &fakeIngestServer{}
	server := setupIngestCLI(t, fake)
	if _, _, err := runRootStdin(t, `{"fields":{"full_name":"x"}}`, "ingest", "--server", server); err == nil {
		t.Fatal("ingest with no entity returned no error")
	}
}

// A server rejection (e.g. 403) surfaces as a command error and stops the
// run.
func TestIngestSurfacesServerError(t *testing.T) {
	fake := &fakeIngestServer{failStatus: http.StatusForbidden}
	server := setupIngestCLI(t, fake)
	file := writeJSONFile(t, `{"fields":{"full_name":"x"}}`)
	if _, _, err := runRoot(t, "ingest", "patient", "--file", file, "--server", server); err == nil {
		t.Fatal("ingest against a forbidding server returned no error")
	}
}

// Empty input is a usage error — there is nothing to ingest.
func TestIngestRejectsEmptyInput(t *testing.T) {
	fake := &fakeIngestServer{}
	server := setupIngestCLI(t, fake)
	file := writeJSONFile(t, `[]`)
	if _, _, err := runRoot(t, "ingest", "patient", "--file", file, "--server", server); err == nil {
		t.Fatal("ingest with an empty array returned no error")
	}
}
