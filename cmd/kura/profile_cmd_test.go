package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bensyverson/kura/internal/clio"
	"github.com/spf13/pflag"
)

// `kura profile list` on an empty config dir reports "no profiles
// configured" — the agent learns the empty state without grepping the
// filesystem.
func TestProfileListEmpty(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	stdout, _, err := runRoot(t, "profile", "list")
	if err != nil {
		t.Fatalf("profile list (empty): %v", err)
	}
	if !strings.Contains(stdout.String(), "no profiles configured") {
		t.Errorf("stdout = %q, want it to mention the empty state", stdout.String())
	}
}

// `kura profile add` writes a client profile to the config file. Round
// trip: list immediately after add returns the new profile.
func TestProfileAddThenList(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	if _, _, err := runRoot(t, "profile", "add", "--name", "acme", "--endpoint", "https://kura.acme.example"); err != nil {
		t.Fatalf("profile add: %v", err)
	}
	stdout, _, err := runRoot(t, "profile", "list")
	if err != nil {
		t.Fatalf("profile list: %v", err)
	}
	for _, want := range []string{"acme", "https://kura.acme.example"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("stdout = %q, want it to contain %q", stdout.String(), want)
		}
	}
}

// --json mode emits a stable schema: the list of clients with their
// endpoints. The masking-invariance rule applies — both formats show
// the same fields.
func TestProfileListJSON(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	if _, _, err := runRoot(t, "profile", "add", "--name", "acme", "--endpoint", "https://kura.acme.example"); err != nil {
		t.Fatalf("profile add: %v", err)
	}
	stdout, _, err := runRoot(t, "profile", "list", "--json")
	if err != nil {
		t.Fatalf("profile list --json: %v", err)
	}
	var doc map[string]any
	if err := json.NewDecoder(&stdout).Decode(&doc); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	clients, _ := doc["clients"].(map[string]any)
	acme, _ := clients["acme"].(map[string]any)
	if got, _ := acme["endpoint"].(string); got != "https://kura.acme.example" {
		t.Errorf("clients.acme.endpoint = %v, want https://kura.acme.example", got)
	}
}

// profile add with no --endpoint is a usage error. The error names the
// missing flag — fix-in-the-line.
func TestProfileAddRequiresEndpoint(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	_, _, err := runRoot(t, "profile", "add", "--name", "acme")
	if err == nil {
		t.Fatal("profile add with no --endpoint returned no error")
	}
	var ce *clio.Error
	if !errors.As(err, &ce) || ce.Kind != clio.KindUsage {
		t.Errorf("Kind = %v, want KindUsage; err = %v", ce, err)
	}
	if !strings.Contains(err.Error(), "--endpoint") {
		t.Errorf("error %q does not name --endpoint as the fix", err)
	}
}

// profile add refuses to overwrite an existing client — a Conflict.
// An agent that wants to swap an endpoint runs `profile remove` then
// `profile add`, so the previous value is never silently lost.
func TestProfileAddRefusesToOverwrite(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	if _, _, err := runRoot(t, "profile", "add", "--name", "acme", "--endpoint", "https://kura.acme.example"); err != nil {
		t.Fatalf("profile add (first): %v", err)
	}
	_, _, err := runRoot(t, "profile", "add", "--name", "acme", "--endpoint", "https://kura.other.example")
	if err == nil {
		t.Fatal("profile add accepted an overwrite — must refuse")
	}
	if clio.ExitCode(err) != 5 {
		t.Errorf("ExitCode = %d, want 5 (conflict)", clio.ExitCode(err))
	}
}

// profile remove deletes a client. list afterwards no longer mentions it.
func TestProfileRemove(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	if _, _, err := runRoot(t, "profile", "add", "--name", "acme", "--endpoint", "https://kura.acme.example"); err != nil {
		t.Fatalf("profile add: %v", err)
	}
	if _, _, err := runRoot(t, "profile", "remove", "--name", "acme"); err != nil {
		t.Fatalf("profile remove: %v", err)
	}
	stdout, _, err := runRoot(t, "profile", "list")
	if err != nil {
		t.Fatalf("profile list: %v", err)
	}
	if strings.Contains(stdout.String(), "acme") {
		t.Errorf("removed client still present in list: %q", stdout.String())
	}
}

// profile remove on an unknown name is a NotFound error with the
// enumerating message the loader emits — the agent sees the menu of
// configured clients in one line.
func TestProfileRemoveUnknownEnumerates(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	if _, _, err := runRoot(t, "profile", "add", "--name", "acme", "--endpoint", "https://kura.acme.example"); err != nil {
		t.Fatalf("profile add: %v", err)
	}
	_, _, err := runRoot(t, "profile", "remove", "--name", "missing")
	if err == nil {
		t.Fatal("profile remove accepted an unknown name")
	}
	if clio.ExitCode(err) != 4 {
		t.Errorf("ExitCode = %d, want 4 (not-found)", clio.ExitCode(err))
	}
	if !strings.Contains(err.Error(), "acme") {
		t.Errorf("error %q does not enumerate the known clients", err)
	}
}

// Structural defense (E3V criterion at the writer side): the
// profile-add command has no flag that could carry a credential. We
// pin this by asserting the only flags add registers are --name and
// --endpoint. A future commit that adds --token will fail this test
// before it can ship.
func TestProfileAddCommandHasNoCredentialFlags(t *testing.T) {
	root := newRootCmd()
	profile, _, err := root.Find([]string{"profile", "add"})
	if err != nil {
		t.Fatalf("locating profile add: %v", err)
	}
	allowed := map[string]bool{"name": true, "endpoint": true}
	profile.Flags().VisitAll(func(f *pflag.Flag) {
		if !allowed[f.Name] {
			t.Errorf("profile add has a non-allowed flag %q — credentials never live in profiles", f.Name)
		}
	})
}

// On-disk: after profile add, the config file does not contain any
// credential-shaped string. We pin the absence of a token field
// concretely — if a future change writes one in, this test fails
// before a credential leaks to disk.
func TestProfileAddDoesNotWriteCredentialField(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	if _, _, err := runRoot(t, "profile", "add", "--name", "acme", "--endpoint", "https://kura.acme.example"); err != nil {
		t.Fatalf("profile add: %v", err)
	}
	path, err := defaultProfilesPath()
	if err != nil {
		t.Fatalf("defaultProfilesPath: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	for _, banned := range []string{"\"token\"", "\"secret\"", "\"password\"", "\"key\""} {
		if strings.Contains(string(body), banned) {
			t.Errorf("profile config file contains %q — credentials never live in profiles:\n%s", banned, body)
		}
	}
	// And the loader (the reader side) re-rejects any such field if it
	// turns up in a hand-edited file. Belt and braces — the writer-side
	// rule above is the structural defense; this is the loader-side
	// gate. Inject a token field by hand and confirm the load fails.
	tampered := strings.Replace(string(body), `"endpoint"`, `"token": "leaked", "endpoint"`, 1)
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}
	if _, err := loadProfilesFrom(path); err == nil {
		t.Fatal("loader silently accepted a tampered profile with a token field")
	}
	// Cleanup so subsequent t.TempDir teardown can run.
	t.Cleanup(func() { _ = os.Remove(filepath.Join(filepath.Dir(path), "config.json")) })
}

// End-to-end: `kura --client acme whoami` resolves the endpoint via
// the saved profile, hits the right server, and prints the principal.
// This is criterion om6 at the CLI-call level (the unit tests in
// cliconfig_test.go cover the resolveServer rules in isolation).
func TestClientFlagResolvesViaProfileEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type": "consultant", "email": "alex@firm.example",
			"tenant": "firm.example", "id": "alex@firm.example",
		})
	}))
	defer srv.Close()

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	// Register the profile and the cached credential.
	if _, _, err := runRoot(t, "profile", "add", "--name", "acme", "--endpoint", srv.URL); err != nil {
		t.Fatalf("profile add: %v", err)
	}
	cache, _ := defaultTokenCache()
	if err := cache.save("https://other.example", "tok"); err != nil {
		t.Fatalf("cache save: %v", err)
	}

	stdout, _, err := runRoot(t, "whoami", "--client", "acme", "--json")
	if err != nil {
		t.Fatalf("whoami --client acme: %v", err)
	}
	if !strings.Contains(stdout.String(), "alex@firm.example") {
		t.Errorf("whoami did not use the profile endpoint: %q", stdout.String())
	}
}
