package main

import (
	"strings"
	"testing"
)

// resolveServer returns whichever server URL the precedence rules
// select: --server (explicit) wins over --client (profile lookup), and
// either wins over a cached credential.
func TestResolveServerExplicitFlagWins(t *testing.T) {
	got, err := resolveServer(serverInputs{
		flag:     "https://kura.flag.example",
		client:   "acme",
		profiles: testProfilesWith(map[string]string{"acme": "https://kura.acme.example"}),
		cached:   "https://kura.cached.example",
	})
	if err != nil {
		t.Fatalf("resolveServer: %v", err)
	}
	if got != "https://kura.flag.example" {
		t.Errorf("resolveServer = %q, want the --server value", got)
	}
}

// With no --server flag, the named client profile wins over the cache.
func TestResolveServerClientProfileBeatsCache(t *testing.T) {
	got, err := resolveServer(serverInputs{
		flag:     "",
		client:   "acme",
		profiles: testProfilesWith(map[string]string{"acme": "https://kura.acme.example"}),
		cached:   "https://kura.cached.example",
	})
	if err != nil {
		t.Fatalf("resolveServer: %v", err)
	}
	if got != "https://kura.acme.example" {
		t.Errorf("resolveServer = %q, want the --client value", got)
	}
}

// With neither --server nor --client, the cached credential's server is
// the fallback — `kura login` has set it.
func TestResolveServerCacheFallback(t *testing.T) {
	got, err := resolveServer(serverInputs{
		flag:     "",
		client:   "",
		profiles: testProfilesWith(nil),
		cached:   "https://kura.cached.example",
	})
	if err != nil {
		t.Fatalf("resolveServer: %v", err)
	}
	if got != "https://kura.cached.example" {
		t.Errorf("resolveServer = %q, want the cached value", got)
	}
}

// With none of the three, a remote-mode invocation has no idea what to
// hit — fail loudly and name the three ways to fix it.
func TestResolveServerNoneIsAnError(t *testing.T) {
	_, err := resolveServer(serverInputs{
		flag:     "",
		client:   "",
		profiles: testProfilesWith(nil),
		cached:   "",
	})
	if err == nil {
		t.Fatal("resolveServer returned no error with no inputs")
	}
	for _, want := range []string{"--server", "--client", "kura login"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q as a fix", err, want)
		}
	}
}

// An unknown --client name surfaces the profile loader's enumerating
// error, untouched, so the agent gets the same message the profile
// layer would emit directly.
func TestResolveServerUnknownClientPropagatesError(t *testing.T) {
	_, err := resolveServer(serverInputs{
		flag:     "",
		client:   "missing",
		profiles: testProfilesWith(map[string]string{"acme": "https://x"}),
		cached:   "https://anything",
	})
	if err == nil {
		t.Fatal("resolveServer accepted an unknown --client")
	}
	if !strings.Contains(err.Error(), "missing") || !strings.Contains(err.Error(), "acme") {
		t.Errorf("error %q must mention the bad name and the known names", err)
	}
}

// testProfilesWith builds an in-memory profiles set from a name→endpoint
// map. nil m yields an empty profiles set.
func testProfilesWith(m map[string]string) *profiles {
	clients := map[string]profileClient{}
	for name, endpoint := range m {
		clients[name] = profileClient{Endpoint: endpoint}
	}
	return &profiles{Version: "1", Clients: clients}
}
