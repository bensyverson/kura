package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bensyverson/kura/internal/ops"
)

// fakeEraseServer stands in for kura serve's erasure endpoint: it records
// the record ids it was asked to shred and returns a fixed shredded count.
type fakeEraseServer struct {
	gotIDs   []string
	shredded int
	called   bool
}

func (f *fakeEraseServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/erase", func(w http.ResponseWriter, r *http.Request) {
		f.called = true
		var body struct {
			RecordIDs []string `json:"record_ids"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		io.Copy(io.Discard, r.Body)
		f.gotIDs = body.RecordIDs
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"shredded": f.shredded})
	})
	return mux
}

// setupEraseCLI stands up a fake erasure server and primes the token cache
// so `kura erase` can address it.
func setupEraseCLI(t *testing.T, fake *fakeEraseServer) string {
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

// `kura erase` is wired as a real command.
func TestEraseCommandIsWired(t *testing.T) {
	root := newRootCmd()
	erase, _, err := root.Find([]string{"erase"})
	if err != nil {
		t.Fatalf("finding erase command: %v", err)
	}
	if erase.Name() != "erase" {
		t.Fatalf("found command %q, want erase", erase.Name())
	}
}

// With --confirm, `kura erase` shreds the named records and reports how many
// keys were destroyed, sending exactly the ids it was given.
func TestEraseShredsRecords(t *testing.T) {
	fake := &fakeEraseServer{shredded: 3}
	server := setupEraseCLI(t, fake)

	stdout, _, err := runRoot(t, "erase", "r1", "r2", "--confirm", "--server", server)
	if err != nil {
		t.Fatalf("erase: %v", err)
	}
	if len(fake.gotIDs) != 2 || fake.gotIDs[0] != "r1" || fake.gotIDs[1] != "r2" {
		t.Errorf("server got ids %v, want [r1 r2]", fake.gotIDs)
	}
	if !strings.Contains(stdout.String(), "3") {
		t.Errorf("output %q does not report the shredded count", stdout.String())
	}
}

// Erasure is destructive, so --confirm is mandatory: without it the command
// is a usage error and the server is never called.
func TestEraseRequiresConfirm(t *testing.T) {
	fake := &fakeEraseServer{}
	server := setupEraseCLI(t, fake)

	if _, _, err := runRoot(t, "erase", "r1", "--server", server); err == nil {
		t.Fatal("erase without --confirm returned no error")
	}
	if fake.called {
		t.Error("server was called despite a missing --confirm")
	}
}

// At least one record id is required: erase with no ids is a usage error,
// rejected before any server call.
func TestEraseRequiresRecordIDs(t *testing.T) {
	fake := &fakeEraseServer{}
	server := setupEraseCLI(t, fake)

	if _, _, err := runRoot(t, "erase", "--confirm", "--server", server); err == nil {
		t.Fatal("erase with no record ids returned no error")
	}
	if fake.called {
		t.Error("server was called despite no record ids")
	}
}

// erase is declared in the ops registry — the seam projected onto
// agent-context and MCP — with an explicit record-ids arg and no domain
// language, and as a declaration-only entry (nil handler) so its command is
// the hand-written newEraseCmd, not an auto-generated stub.
func TestEraseRegisteredInOpsRegistry(t *testing.T) {
	r := buildRegistry(newRootCmd())
	var found *ops.Operation
	for _, op := range r.All() {
		if op.Name == "erase" {
			op := op
			found = &op
			break
		}
	}
	if found == nil {
		t.Fatal("erase is not registered in the ops Registry")
	}
	if found.Summary == "" {
		t.Error("the erase operation is missing its summary")
	}
	if found.Handler != nil {
		t.Error("the erase operation must be declaration-only (nil handler); its command is newEraseCmd")
	}
	if len(found.Args) != 1 || found.Args[0].Name != "record_ids" || !found.Args[0].Required {
		t.Errorf("erase args = %+v, want one required record_ids arg", found.Args)
	}
	// Domain-agnostic: no CRM/subject vocabulary may leak into the verb.
	var blob strings.Builder
	blob.WriteString(strings.ToLower(found.Name + " " + found.Summary))
	for _, a := range found.Args {
		blob.WriteString(" " + strings.ToLower(a.Name+" "+a.Summary))
	}
	for _, banned := range []string{"subject", "party", "customer", "lifecycle"} {
		if strings.Contains(blob.String(), banned) {
			t.Errorf("erase operation leaks domain language %q: %q", banned, blob.String())
		}
	}
}

// The hand-written command and the registry declaration cannot drift: both
// are wired to the same shared name/summary constants.
func TestEraseCommandMatchesRegistryDeclaration(t *testing.T) {
	r := buildRegistry(newRootCmd())
	var summary string
	for _, op := range r.All() {
		if op.Name == "erase" {
			summary = op.Summary
		}
	}
	cmd := newEraseCmd()
	if !strings.HasPrefix(cmd.Use, "erase") {
		t.Errorf("command Use = %q, want it to start with erase", cmd.Use)
	}
	if cmd.Short != summary {
		t.Errorf("command Short %q != registry summary %q", cmd.Short, summary)
	}
}
