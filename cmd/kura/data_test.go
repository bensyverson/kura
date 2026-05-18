package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeDataServer is the stand-in for `kura serve`'s data surface that
// `kura query` and `kura show` talk to. It returns whatever masked
// records the test seeds, applies a server-side limit clamp that
// mirrors the gate's bounds (DefaultPageSize=50, MaxPageSize=200), and
// records the limit/offset query parameters it actually saw — so a
// test can pin that the CLI passes through bounds rather than fighting
// them.
type fakeDataServer struct {
	t         *testing.T
	mu        sync.Mutex
	records   map[string]map[string]map[string]string // entity -> id -> fields
	pageOrder map[string][]string                     // entity -> ordered ids
	calls     []dataCall
}

type dataCall struct {
	method string
	path   string
	query  string
}

func newFakeDataServer(t *testing.T) *fakeDataServer {
	return &fakeDataServer{
		t:         t,
		records:   map[string]map[string]map[string]string{},
		pageOrder: map[string][]string{},
	}
}

func (f *fakeDataServer) put(entity, id string, fields map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.records[entity]; !ok {
		f.records[entity] = map[string]map[string]string{}
	}
	if _, exists := f.records[entity][id]; !exists {
		f.pageOrder[entity] = append(f.pageOrder[entity], id)
	}
	f.records[entity][id] = fields
}

func (f *fakeDataServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/{entity}", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		entity := r.PathValue("entity")
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		// Mirror gate bounds so the test can pin clamping.
		if limit <= 0 {
			limit = 50
		}
		if limit > 200 {
			limit = 200
		}
		if offset < 0 {
			offset = 0
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		order := f.pageOrder[entity]
		type rec struct {
			ID     string            `json:"id"`
			Fields map[string]string `json:"fields"`
		}
		page := struct {
			Records []rec `json:"records"`
			Limit   int   `json:"limit"`
			Offset  int   `json:"offset"`
		}{Limit: limit, Offset: offset, Records: []rec{}}
		end := min(offset+limit, len(order))
		if offset < len(order) {
			for _, id := range order[offset:end] {
				page.Records = append(page.Records, rec{ID: id, Fields: f.records[entity][id]})
			}
		}
		_ = json.NewEncoder(w).Encode(page)
	})
	mux.HandleFunc("GET /api/{entity}/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		entity := r.PathValue("entity")
		id := r.PathValue("id")
		f.mu.Lock()
		defer f.mu.Unlock()
		fields, ok := f.records[entity][id]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(fields)
	})
	return mux
}

func (f *fakeDataServer) record(r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, dataCall{method: r.Method, path: r.URL.Path, query: r.URL.RawQuery})
}

func setupDataCLITest(t *testing.T, fake *fakeDataServer) string {
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

// YFc: `kura query <entity>` works for every entity in a test manifest
// — the verb takes the entity as an argument, so the same code path
// serves any entity name the server has a route for. Two distinct
// entities, two query calls, both succeed.
func TestQueryWorksForEveryEntityInManifest(t *testing.T) {
	fake := newFakeDataServer(t)
	fake.put("patient", "p1", map[string]string{"full_name": "Alex Doe"})
	fake.put("visit", "v1", map[string]string{"reason": "checkup"})
	server := setupDataCLITest(t, fake)

	for _, entity := range []string{"patient", "visit"} {
		stdout, _, err := runRoot(t, "query", entity, "--server", server)
		if err != nil {
			t.Fatalf("query %s: %v", entity, err)
		}
		if !strings.Contains(stdout.String(), entity) {
			t.Errorf("query %s output missing entity name:\n%s", entity, stdout.String())
		}
	}
}

// YFc: `kura show <entity> <id>` works for every entity — same
// argument-driven shape, no per-entity wiring. Two entities seeded,
// each fetched and rendered.
func TestShowWorksForEveryEntityInManifest(t *testing.T) {
	fake := newFakeDataServer(t)
	fake.put("patient", "p1", map[string]string{"full_name": "Alex Doe"})
	fake.put("visit", "v1", map[string]string{"reason": "checkup"})
	server := setupDataCLITest(t, fake)

	for _, c := range []struct {
		entity, id, want string
	}{
		{"patient", "p1", "Alex Doe"},
		{"visit", "v1", "checkup"},
	} {
		stdout, _, err := runRoot(t, "show", c.entity, c.id, "--server", server)
		if err != nil {
			t.Fatalf("show %s %s: %v", c.entity, c.id, err)
		}
		if !strings.Contains(stdout.String(), c.want) {
			t.Errorf("show %s %s missing %q:\n%s", c.entity, c.id, c.want, stdout.String())
		}
	}
}

// ETx: masked field values pass through unchanged — the CLI is a
// presenter over the gate's response, not a second masking layer or an
// unmasker. A masked field value (the placeholder the gate stamps in)
// shows up verbatim in both Markdown and JSON.
func TestShowSurfacesServerMaskingUnchanged(t *testing.T) {
	fake := newFakeDataServer(t)
	fake.put("patient", "p1", map[string]string{
		"full_name": "<masked: person>",
		"age":       "30",
	})
	server := setupDataCLITest(t, fake)

	md, _, err := runRoot(t, "show", "patient", "p1", "--server", server)
	if err != nil {
		t.Fatalf("show markdown: %v", err)
	}
	js, _, err := runRoot(t, "show", "patient", "p1", "--server", server, "--json")
	if err != nil {
		t.Fatalf("show json: %v", err)
	}
	for _, want := range []string{"<masked: person>", "30"} {
		if !strings.Contains(md.String(), want) {
			t.Errorf("markdown view missing %q:\n%s", want, md.String())
		}
	}
	// JSON encodes < as < by default; decode and assert on the
	// field value so a string-contains check does not get tripped up by
	// HTML escaping that is a presentation detail of encoding/json.
	var got struct {
		Fields map[string]string `json:"fields"`
	}
	if err := json.NewDecoder(&js).Decode(&got); err != nil {
		t.Fatalf("decode show json: %v", err)
	}
	if got.Fields["full_name"] != "<masked: person>" {
		t.Errorf("json full_name = %q, want %q", got.Fields["full_name"], "<masked: person>")
	}
	if got.Fields["age"] != "30" {
		t.Errorf("json age = %q, want 30", got.Fields["age"])
	}
}

// ETx: query is bounded by default. With no --limit, the server reports
// back its DefaultPageSize, and the CLI surfaces that effective bound —
// so an agent that did not pass --limit knows the page is bounded and
// what the bound was.
func TestQueryIsBoundedByDefault(t *testing.T) {
	fake := newFakeDataServer(t)
	for i := range 75 {
		fake.put("patient", "p"+strconv.Itoa(i), map[string]string{"k": "v"})
	}
	server := setupDataCLITest(t, fake)

	stdout, _, err := runRoot(t, "query", "patient", "--server", server, "--json")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	var page struct {
		Records []json.RawMessage `json:"records"`
		Limit   int               `json:"limit"`
	}
	if err := json.NewDecoder(&stdout).Decode(&page); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout.String())
	}
	if page.Limit != 50 {
		t.Errorf("effective limit = %d, want 50 (DefaultPageSize)", page.Limit)
	}
	if len(page.Records) != 50 {
		t.Errorf("returned %d records, want 50 — the default bound should kick in", len(page.Records))
	}
}

// ETx: query --limit >MaxPageSize is silently clamped by the server,
// and the CLI's --limit doesn't try to fight that. The agent reads the
// effective limit back from the response.
func TestQueryRespectsServerSideClamp(t *testing.T) {
	fake := newFakeDataServer(t)
	for i := range 300 {
		fake.put("patient", "p"+strconv.Itoa(i), map[string]string{"k": "v"})
	}
	server := setupDataCLITest(t, fake)

	stdout, _, err := runRoot(t, "query", "patient", "--server", server, "--limit", "10000", "--json")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	var page struct {
		Records []json.RawMessage `json:"records"`
		Limit   int               `json:"limit"`
	}
	if err := json.NewDecoder(&stdout).Decode(&page); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if page.Limit != 200 {
		t.Errorf("effective limit = %d, want 200 (MaxPageSize clamp)", page.Limit)
	}
}

// `kura query --limit N --offset M` passes through to the server query
// parameters — the server is the one source of truth for clamping,
// and the CLI must hand it the agent's intent verbatim.
func TestQueryPassesLimitAndOffsetThrough(t *testing.T) {
	fake := newFakeDataServer(t)
	for i := range 20 {
		fake.put("patient", "p"+strconv.Itoa(i), map[string]string{"k": "v"})
	}
	server := setupDataCLITest(t, fake)

	_, _, err := runRoot(t, "query", "patient", "--server", server, "--limit", "5", "--offset", "3", "--json")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if got := fake.calls[len(fake.calls)-1].query; !strings.Contains(got, "limit=5") || !strings.Contains(got, "offset=3") {
		t.Errorf("server saw query %q, want limit=5 and offset=3", got)
	}
}

// `kura query <entity>` with no records on the page reports the empty
// state explicitly, so an agent does not have to grep for an empty
// records array.
func TestQueryEmptyPageRendersExplicitly(t *testing.T) {
	fake := newFakeDataServer(t)
	server := setupDataCLITest(t, fake)

	stdout, _, err := runRoot(t, "query", "patient", "--server", server)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if !strings.Contains(stdout.String(), "no records") {
		t.Errorf("empty page should say so explicitly:\n%s", stdout.String())
	}
}

// `kura show <entity> <unknown>` is a NotFound (KindNotFound, exit 4)
// per the shared HTTP-status taxonomy. The error message folds in the
// server's body, so the agent's first line names what was missing.
func TestShowUnknownIsNotFound(t *testing.T) {
	fake := newFakeDataServer(t)
	server := setupDataCLITest(t, fake)

	_, _, err := runRoot(t, "show", "patient", "ghost-id", "--server", server)
	if err == nil {
		t.Fatal("expected NotFound for missing record")
	}
	if !strings.Contains(err.Error(), "show: ") {
		t.Errorf("error %q does not have the show: prefix", err)
	}
}

// `kura query` and `kura show` are usage errors when the positional
// shape is wrong — the agent gets the fix on the first line.
func TestQueryAndShowRequirePositionalArgs(t *testing.T) {
	fake := newFakeDataServer(t)
	server := setupDataCLITest(t, fake)

	if _, _, err := runRoot(t, "query", "--server", server); err == nil || !strings.Contains(err.Error(), "entity name") {
		t.Errorf("query with no entity: err = %v, want usage error naming entity", err)
	}
	if _, _, err := runRoot(t, "show", "patient", "--server", server); err == nil || !strings.Contains(err.Error(), "entity name and one id") {
		t.Errorf("show with no id: err = %v, want usage error naming entity+id", err)
	}
}
