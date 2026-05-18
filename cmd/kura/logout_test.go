package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bensyverson/kura/internal/clio"
)

// kura logout deletes the cached credential. The next remote command
// will therefore hit the "no cached credential" path until `kura
// login` runs again.
func TestLogoutDeletesCachedCredential(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	cache, err := defaultTokenCache()
	if err != nil {
		t.Fatalf("defaultTokenCache: %v", err)
	}
	if err := cache.save("https://kura.example", "cached-token"); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cache.dir, "credentials.json")); err != nil {
		t.Fatalf("credential file not where the cache says: %v", err)
	}

	stdout, _, err := runRoot(t, "logout")
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cache.dir, "credentials.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("logout did not delete the credential file: err=%v", err)
	}
	// The ack must say what changed — the agent reads stdout to confirm.
	if !strings.Contains(stdout.String(), "Signed out") {
		t.Errorf("logout stdout = %q, want it to confirm sign-out", stdout.String())
	}
}

// Idempotent: logout with no cached credential is a clean no-op, not a
// usage or auth error. The agent must be able to call it without
// branching on prior state.
func TestLogoutIsIdempotent(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	stdout, _, err := runRoot(t, "logout")
	if err != nil {
		t.Fatalf("logout on empty cache: %v", err)
	}
	if !strings.Contains(stdout.String(), "no cached credential") &&
		!strings.Contains(stdout.String(), "Signed out") {
		t.Errorf("logout stdout = %q, want it to mention the no-op or sign-out", stdout.String())
	}
}

// On an OS-level delete failure (read-only directory), logout returns a
// classified internal error — not a silent success. The greppable
// prefix is `logout: `.
func TestLogoutSurfacesUnexpectedDeleteFailureAsInternal(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_CONFIG_HOME", tmp)
	cache, _ := defaultTokenCache()
	if err := cache.save("https://kura.example", "tok"); err != nil {
		t.Fatalf("save: %v", err)
	}
	// Make the directory read-only so os.Remove fails. Restore
	// permissions in a cleanup hook so the tempdir teardown can run.
	if err := os.Chmod(cache.dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(cache.dir, 0o700) })

	_, _, err := runRoot(t, "logout")
	if err == nil {
		t.Skip("filesystem allowed the delete despite read-only parent — cannot exercise this path here")
	}
	var ce *clio.Error
	if !errors.As(err, &ce) {
		t.Fatalf("error %T is not a *clio.Error", err)
	}
	if ce.Kind != clio.KindInternal {
		t.Errorf("Kind = %v, want KindInternal", ce.Kind)
	}
	if !strings.HasPrefix(err.Error(), "logout: ") {
		t.Errorf("error %q does not have greppable `logout: ` prefix", err)
	}
}
