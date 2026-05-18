package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bensyverson/kura/internal/clio"
)

// kura status against a configured server orients an agent cold: it
// reports the resolved server URL, the principal identity from
// /api/whoami, and a tier note (placeholder until Phase 6 wires the
// real deployment tier). The criterion 73y says "server, identity,
// tier, anomalies" — the first two carry real data now; the last two
// are pinned as known placeholders so an agent can read the document
// without inferring missing fields.
func TestStatusJSONShowsServerIdentityAndTier(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/whoami" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type":   "consultant",
			"id":     "alex@firm.example",
			"email":  "alex@firm.example",
			"tenant": "firm.example",
		})
	}))
	defer srv.Close()

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cache, _ := defaultTokenCache()
	if err := cache.save(srv.URL, "tok"); err != nil {
		t.Fatalf("save: %v", err)
	}

	stdout, _, err := runRoot(t, "status", "--json")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	var doc map[string]any
	if err := json.NewDecoder(&stdout).Decode(&doc); err != nil {
		t.Fatalf("decoding: %v\nstdout=%q", err, stdout.String())
	}
	if got := doc["server"]; got != srv.URL {
		t.Errorf("server = %v, want %q", got, srv.URL)
	}
	identity, _ := doc["identity"].(map[string]any)
	if got, _ := identity["email"].(string); got != "alex@firm.example" {
		t.Errorf("identity.email = %q, want alex@firm.example", got)
	}
	if got, _ := identity["type"].(string); got != "consultant" {
		t.Errorf("identity.type = %q, want consultant", got)
	}
	if _, ok := doc["tier"]; !ok {
		t.Error("status JSON missing the `tier` field (placeholder is fine; absence is not)")
	}
	if _, ok := doc["anomalies"]; !ok {
		t.Error("status JSON missing the `anomalies` field")
	}
}

// The Markdown view shows the same fields as the JSON view — masking
// invariance again. An agent reading either gets the same orientation.
func TestStatusMarkdownShowsServerAndIdentity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type":  "user",
			"email": "alex@client.example", "tenant": "client.example", "id": "alex@client.example",
		})
	}))
	defer srv.Close()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cache, _ := defaultTokenCache()
	_ = cache.save(srv.URL, "tok")

	stdout, _, err := runRoot(t, "status")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	for _, want := range []string{srv.URL, "alex@client.example", "user", "client.example"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("markdown view missing %q:\n%s", want, stdout.String())
		}
	}
}

// status with no server config is the same usage error every remote
// command surfaces — pinned for greppability.
func TestStatusFailsLoudlyWithoutServer(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	_, _, err := runRoot(t, "status")
	if err == nil {
		t.Fatal("status with no server returned no error")
	}
	var ce *clio.Error
	if !errors.As(err, &ce) {
		t.Fatalf("error %T is not classified", err)
	}
	if ce.Kind != clio.KindUsage {
		t.Errorf("Kind = %v, want KindUsage", ce.Kind)
	}
	if !strings.HasPrefix(err.Error(), "status: ") {
		t.Errorf("error %q has no greppable `status: ` prefix", err)
	}
}

// A 5xx server makes status fail with a Transient error — same
// classification as whoami uses for the same condition.
func TestStatusClassifies5xxAsTransient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal boom", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cache, _ := defaultTokenCache()
	_ = cache.save(srv.URL, "tok")

	_, _, err := runRoot(t, "status")
	if err == nil {
		t.Fatal("status against a 5xx returned no error")
	}
	if clio.ExitCode(err) != 6 {
		t.Errorf("ExitCode = %d, want 6 (transient)", clio.ExitCode(err))
	}
}
