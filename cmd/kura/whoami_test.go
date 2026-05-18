package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runRoot is a small driver: build the root command, set its argv and
// IO buffers, and execute. It returns stdout, stderr, and the error.
func runRoot(t *testing.T, args ...string) (stdout, stderr bytes.Buffer, err error) {
	t.Helper()
	root := newRootCmd()
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs(args)
	err = root.Execute()
	return
}

// In --local mode, `kura whoami --as alex@firm.example` resolves
// alex@firm.example as a Consultant when firm.example is the configured
// firm tenant. The same identity.TenantTrust the server uses on the
// oauth callback decides the type here too.
func TestWhoamiLocalResolvesConsultant(t *testing.T) {
	t.Setenv("KURA_FIRM_DOMAIN", "firm.example")
	t.Setenv("KURA_CLIENT_DOMAINS", "client.example")
	t.Setenv("KURA_ADMIN_EMAILS", "")
	stdout, _, err := runRoot(t, "whoami", "--local", "--as", "alex@firm.example", "--json")
	if err != nil {
		t.Fatalf("whoami --local: %v", err)
	}
	var p map[string]any
	if err := json.NewDecoder(&stdout).Decode(&p); err != nil {
		t.Fatalf("decoding output: %v\nstdout=%q", err, stdout.String())
	}
	if got, _ := p["type"].(string); got != "consultant" {
		t.Errorf("type = %q, want consultant", got)
	}
	if got, _ := p["email"].(string); got != "alex@firm.example" {
		t.Errorf("email = %q, want alex@firm.example", got)
	}
}

// A client-domain email resolves to User; the admin allowlist promotes
// it to Admin. Same TenantTrust shape, end-to-end through --local.
func TestWhoamiLocalAdminAllowlist(t *testing.T) {
	t.Setenv("KURA_FIRM_DOMAIN", "firm.example")
	t.Setenv("KURA_CLIENT_DOMAINS", "client.example")
	t.Setenv("KURA_ADMIN_EMAILS", "boss@client.example")
	stdout, _, err := runRoot(t, "whoami", "--local", "--as", "boss@client.example", "--json")
	if err != nil {
		t.Fatalf("whoami --local: %v", err)
	}
	var p map[string]any
	if err := json.NewDecoder(&stdout).Decode(&p); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if got, _ := p["type"].(string); got != "admin" {
		t.Errorf("type = %q, want admin", got)
	}
}

// --local without --as is an error that names the missing flag — the
// agent gets the fix in the first line.
func TestWhoamiLocalRequiresAs(t *testing.T) {
	t.Setenv("KURA_FIRM_DOMAIN", "firm.example")
	_, _, err := runRoot(t, "whoami", "--local")
	if err == nil {
		t.Fatal("whoami --local with no --as returned no error")
	}
	if !strings.Contains(err.Error(), "--as") {
		t.Errorf("error %q does not name --as as the fix", err)
	}
}

// In remote mode (no --local), whoami GETs /api/whoami at the resolved
// server URL with the cached bearer token, then renders the principal.
// We stand up an httptest server that plays the role of `kura serve`.
func TestWhoamiRemoteHitsAPIWhoami(t *testing.T) {
	var (
		gotPath, gotAuth string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type":   "user",
			"id":     "alex@client.example",
			"email":  "alex@client.example",
			"tenant": "client.example",
		})
	}))
	defer srv.Close()

	// Cache a credential for the fake server. The CLI uses the user's
	// config dir; redirect that to a temp dir for the test.
	// HOME drives os.UserConfigDir on darwin and linux; pointing it at a
	// tempdir keeps the test from touching the developer's real config.
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cache, err := defaultTokenCache()
	if err != nil {
		t.Fatalf("defaultTokenCache: %v", err)
	}
	if err := cache.save(srv.URL, "bearer-from-login"); err != nil {
		t.Fatalf("save: %v", err)
	}
	// Sanity: the cache file is where the loader will look.
	if _, err := os.Stat(filepath.Join(cache.dir, "credentials.json")); err != nil {
		t.Fatalf("credentials file not at expected path: %v", err)
	}

	stdout, _, err := runRoot(t, "whoami", "--server", srv.URL, "--json")
	if err != nil {
		t.Fatalf("whoami remote: %v\nstdout=%s", err, stdout.String())
	}
	if gotPath != "/api/whoami" {
		t.Errorf("server saw path %q, want /api/whoami", gotPath)
	}
	if gotAuth != "Bearer bearer-from-login" {
		t.Errorf("server saw Authorization %q, want %q", gotAuth, "Bearer bearer-from-login")
	}
	var p map[string]any
	if err := json.NewDecoder(&stdout).Decode(&p); err != nil {
		t.Fatalf("decoding stdout: %v\nstdout=%q", err, stdout.String())
	}
	if got, _ := p["email"].(string); got != "alex@client.example" {
		t.Errorf("email passthrough = %q, want alex@client.example", got)
	}
}

// In remote mode with no --server, no --client, and no cached
// credential, the agent gets a one-line error that names all three
// fixes (the resolveServer contract).
func TestWhoamiRemoteFailsLoudlyWithoutServer(t *testing.T) {
	// HOME drives os.UserConfigDir on darwin and linux; pointing it at a
	// tempdir keeps the test from touching the developer's real config.
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	_, _, err := runRoot(t, "whoami")
	if err == nil {
		t.Fatal("whoami with no server returned no error")
	}
	for _, want := range []string{"--server", "--client", "kura login"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q as a fix", err, want)
		}
	}
}
