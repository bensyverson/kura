package main

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"
	"time"
)

// browserFake stands in for opening a real browser: it parses the URL
// the CLI would have launched, pulls out the loopback redirect target,
// and drives the callback itself — optionally tampering with the state
// or the token to exercise the failure paths.
func browserFake(t *testing.T, token, overrideState string) func(string) error {
	t.Helper()
	return func(launchURL string) error {
		u, err := url.Parse(launchURL)
		if err != nil {
			return err
		}
		loopback, err := url.Parse(u.Query().Get("redirect"))
		if err != nil {
			return err
		}
		q := loopback.Query()
		if overrideState != "" {
			q.Set("state", overrideState)
		}
		q.Set("token", token)
		loopback.RawQuery = q.Encode()
		go func() {
			resp, err := http.Get(loopback.String())
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}()
		return nil
	}
}

// The loopback handoff completes: the CLI stands up its loopback
// listener, the (faked) browser drives the server callback, and the CLI
// receives the minted token.
func TestLoginFlowCompletesLoopbackHandoff(t *testing.T) {
	flow := &loginFlow{
		serverURL:   "https://kura.client.example",
		openBrowser: browserFake(t, "minted-kura-token", ""),
		out:         io.Discard,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	token, err := flow.run(ctx)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if token != "minted-kura-token" {
		t.Errorf("token = %q, want minted-kura-token", token)
	}
}

// A callback whose state does not match the one the CLI generated is
// rejected — it must not be a way to inject a foreign token into the
// CLI's loopback listener.
func TestLoginFlowRejectsStateMismatch(t *testing.T) {
	flow := &loginFlow{
		serverURL:   "https://kura.client.example",
		openBrowser: browserFake(t, "attacker-token", "wrong-state"),
		out:         io.Discard,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	if _, err := flow.run(ctx); err == nil {
		t.Error("run accepted a token delivered with a mismatched state")
	}
}

// A cached credential round-trips: what save writes, load reads back.
func TestTokenCacheRoundTrip(t *testing.T) {
	cache := tokenCache{dir: filepath.Join(t.TempDir(), "kura")}
	if err := cache.save("https://kura.client.example", "cached-token"); err != nil {
		t.Fatalf("save: %v", err)
	}
	server, token, err := cache.load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if server != "https://kura.client.example" || token != "cached-token" {
		t.Errorf("loaded (%q, %q), want (https://kura.client.example, cached-token)", server, token)
	}
}

// Loading from an empty cache is a clean "not found", not a crash.
func TestTokenCacheLoadMissing(t *testing.T) {
	cache := tokenCache{dir: filepath.Join(t.TempDir(), "kura")}
	if _, _, err := cache.load(); err == nil {
		t.Error("load from an empty cache returned no error")
	}
}
