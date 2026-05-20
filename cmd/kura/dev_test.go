package main

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bensyverson/kura/internal/data"
	"github.com/bensyverson/kura/internal/identity"
	"github.com/bensyverson/kura/internal/manifest"
	"github.com/bensyverson/kura/internal/pii"
)

// The dev manifest scripts/dev-instance.sh hands to kura serve must stay
// valid — serve fails startup on an unparseable manifest, so a drifted
// dev asset would silently break the whole bring-up.
func TestDevManifestIsValid(t *testing.T) {
	if _, err := manifest.ParseFile("../../scripts/dev/manifest.json"); err != nil {
		t.Fatalf("shipped dev manifest is invalid: %v", err)
	}
}

// `kura dev` is wired, hidden from the public surface, and carries the
// dev-only subcommands the bring-up runway needs.
func TestDevCommandIsHiddenAndWired(t *testing.T) {
	root := newRootCmd()
	dev, _, err := root.Find([]string{"dev"})
	if err != nil {
		t.Fatalf("finding dev command: %v", err)
	}
	if !dev.Hidden {
		t.Error("dev command should be hidden — it is a dev/bootstrap affordance, not public surface")
	}
	for _, sub := range []string{"token", "pii-detector", "seed-users"} {
		if c, _, err := root.Find([]string{"dev", sub}); err != nil || c.Name() != sub {
			t.Errorf("dev subcommand %q not wired (found %v, err %v)", sub, c, err)
		}
	}
}

// `kura dev token` mints a token that verifies against the same signing
// secret and resolves back to the requested principal.
func TestDevTokenMintsResolvableToken(t *testing.T) {
	const secret = "dev-signing-secret"
	t.Setenv("KURA_SIGNING_SECRET", secret)

	stdout, _, err := runRoot(t, "dev", "token",
		"--type", "admin", "--email", "admin@dev.example", "--tenant", "dev.example")
	if err != nil {
		t.Fatalf("dev token: %v", err)
	}
	token := strings.TrimSpace(stdout.String())
	if token == "" {
		t.Fatal("dev token printed nothing")
	}

	p, err := identity.NewAuthenticator([]byte(secret)).Resolve(token)
	if err != nil {
		t.Fatalf("minted token did not resolve: %v", err)
	}
	if p.Type != identity.PrincipalAdmin || p.Email != "admin@dev.example" || p.ID != "admin@dev.example" {
		t.Errorf("resolved principal = %+v, want admin admin@dev.example", p)
	}
}

// A service principal needs no email or tenant, only an id.
func TestDevTokenMintsServicePrincipal(t *testing.T) {
	const secret = "dev-signing-secret"
	t.Setenv("KURA_SIGNING_SECRET", secret)

	stdout, _, err := runRoot(t, "dev", "token", "--type", "service", "--id", "seeder")
	if err != nil {
		t.Fatalf("dev token: %v", err)
	}
	p, err := identity.NewAuthenticator([]byte(secret)).Resolve(strings.TrimSpace(stdout.String()))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if p.Type != identity.PrincipalService || p.ID != "seeder" {
		t.Errorf("resolved principal = %+v, want service seeder", p)
	}
}

// Without a signing secret there is nothing to sign with — a clean error.
func TestDevTokenRequiresSigningSecret(t *testing.T) {
	t.Setenv("KURA_SIGNING_SECRET", "")
	if _, _, err := runRoot(t, "dev", "token", "--type", "service", "--id", "x"); err == nil {
		t.Fatal("dev token with no signing secret returned no error")
	}
}

// With --save the minted token lands in the token cache for the named
// server, so downstream verbs (ingest, query, dashboard) are signed in.
func TestDevTokenSavesToCache(t *testing.T) {
	t.Setenv("KURA_SIGNING_SECRET", "dev-signing-secret")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	if _, _, err := runRoot(t, "dev", "token",
		"--type", "admin", "--email", "a@dev.example", "--tenant", "dev.example",
		"--save", "--server", "http://localhost:8080"); err != nil {
		t.Fatalf("dev token --save: %v", err)
	}
	cache, err := defaultTokenCache()
	if err != nil {
		t.Fatalf("defaultTokenCache: %v", err)
	}
	server, token, err := cache.load()
	if err != nil {
		t.Fatalf("cache.load after --save: %v", err)
	}
	if server != "http://localhost:8080" || token == "" {
		t.Errorf("cache holds (%q, %q), want the dev server and a token", server, token)
	}
}

// The dev PII detector serves the detect contract, finding the patterns a
// dev instance carries (here, an email).
func TestDevPIIDetectorHandlerDetects(t *testing.T) {
	srv := httptest.NewServer(devPIIDetectorHandler())
	defer srv.Close()

	spans, err := pii.NewServiceDetector(srv.URL).Detect(context.Background(), "mail ada@example.com")
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(spans) != 1 || spans[0].Category != pii.CategoryEmail {
		t.Errorf("spans = %+v, want one email span", spans)
	}
}

// applyRoleSeeds adds each user and assigns its roles, so the gate can
// later resolve them — the bootstrap that breaks the no-admin-yet
// chicken-and-egg.
func TestApplyRoleSeeds(t *testing.T) {
	users := data.NewMemUserStore()
	seeds := []roleSeed{
		{email: "admin@dev.example", roles: []string{"admin"}},
		{email: "analyst@dev.example", roles: []string{"user"}},
	}
	if err := applyRoleSeeds(context.Background(), users, seeds); err != nil {
		t.Fatalf("applyRoleSeeds: %v", err)
	}
	got, err := users.Roles(context.Background(), identity.Principal{ID: "admin@dev.example"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "admin" {
		t.Errorf("admin roles = %v, want [admin]", got)
	}
}
