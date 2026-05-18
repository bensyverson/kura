package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A profile resolves a client name to an endpoint. The config file is
// the one place an agent looks up "which server is the deployment for
// engagement <name>?" — credentials never live here.
func TestLoadProfilesReturnsRegisteredClient(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{
		"version": "1",
		"clients": {
			"acme":   {"endpoint": "https://kura.acme.example"},
			"globex": {"endpoint": "https://kura.globex.example"}
		}
	}`), 0o600); err != nil {
		t.Fatalf("seeding profile: %v", err)
	}
	profiles, err := loadProfilesFrom(path)
	if err != nil {
		t.Fatalf("loadProfilesFrom: %v", err)
	}
	got, err := profiles.endpoint("acme")
	if err != nil {
		t.Fatalf("endpoint(acme): %v", err)
	}
	if got != "https://kura.acme.example" {
		t.Errorf("endpoint(acme) = %q, want %q", got, "https://kura.acme.example")
	}
}

// An unknown client name fails loudly and enumerates the configured
// clients so the agent does not have to grep the config to learn what
// is on offer.
func TestLoadProfilesUnknownClientEnumerates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{
		"version": "1",
		"clients": {"acme": {"endpoint": "https://x"}, "globex": {"endpoint": "https://y"}}
	}`), 0o600); err != nil {
		t.Fatalf("seeding profile: %v", err)
	}
	profiles, err := loadProfilesFrom(path)
	if err != nil {
		t.Fatalf("loadProfilesFrom: %v", err)
	}
	_, err = profiles.endpoint("missing")
	if err == nil {
		t.Fatal("expected an error for an unknown client")
	}
	// The error must list the known clients.
	for _, want := range []string{"acme", "globex"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not enumerate %q", err, want)
		}
	}
}

// A missing config file is not an error — profiles are optional. The
// caller can still use --server directly.
func TestLoadProfilesMissingFileReturnsEmpty(t *testing.T) {
	profiles, err := loadProfilesFrom(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("loadProfilesFrom on missing file: %v", err)
	}
	if profiles == nil {
		t.Fatal("loadProfilesFrom returned nil for a missing file")
	}
	// endpoint() against any name must enumerate (an empty set) without panicking.
	if _, err := profiles.endpoint("anything"); err == nil {
		t.Error("expected an unknown-client error against an empty profiles set")
	}
}

// A credential file in profiles is a refusal: tokens are short-lived
// and come from `kura login`, never from a checked-in or hand-edited
// config file. A loader that silently accepted a token field would
// invite operators to do exactly that — make it loud.
func TestLoadProfilesRejectsCredentialsField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{
		"version": "1",
		"clients": {"acme": {"endpoint": "https://x", "token": "leaked"}}
	}`), 0o600); err != nil {
		t.Fatalf("seeding profile: %v", err)
	}
	_, err := loadProfilesFrom(path)
	if err == nil {
		t.Fatal("loadProfilesFrom accepted a token field in the profile — must reject")
	}
	if !strings.Contains(err.Error(), "token") {
		t.Errorf("error %q does not mention token", err)
	}
}
