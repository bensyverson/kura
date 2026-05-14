package main

import "testing"

// serveEnv is a complete set of the environment variables serveConfig
// requires, for tests to start from and then perturb.
func serveEnv() map[string]string {
	return map[string]string{
		"KURA_SIGNING_SECRET":       "a-test-signing-secret",
		"KURA_GOOGLE_CLIENT_ID":     "client-id.apps.googleusercontent.com",
		"KURA_GOOGLE_CLIENT_SECRET": "google-client-secret",
		"KURA_PUBLIC_URL":           "https://kura.client.example",
		"KURA_FIRM_DOMAIN":          "examplefirm.com",
		"KURA_PII_DETECTOR_URL":     "http://127.0.0.1:9100/detect",
		"KURA_CLIENT_DOMAINS":       "client.example",
		"KURA_ADMIN_EMAILS":         "boss@client.example",
	}
}

// serveConfig must fail loudly when a required secret is absent — a
// server with no signing secret cannot mint or verify a token, and must
// not start.
func TestServeConfigRequiresSigningSecret(t *testing.T) {
	env := serveEnv()
	delete(env, "KURA_SIGNING_SECRET")
	if _, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] }); err == nil {
		t.Error("serveConfig returned no error when KURA_SIGNING_SECRET was unset")
	}
}

// serveConfig must fail when the Google OAuth client credentials are
// absent — kura serve cannot broker sign-in without them.
func TestServeConfigRequiresGoogleCredentials(t *testing.T) {
	env := serveEnv()
	delete(env, "KURA_GOOGLE_CLIENT_ID")
	if _, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] }); err == nil {
		t.Error("serveConfig returned no error when KURA_GOOGLE_CLIENT_ID was unset")
	}
}

// serveConfig must fail when the PII detector URL is absent — the gate
// cannot mask without a detector, and a server whose gate cannot mask
// must not start.
func TestServeConfigRequiresDetectorURL(t *testing.T) {
	env := serveEnv()
	delete(env, "KURA_PII_DETECTOR_URL")
	if _, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] }); err == nil {
		t.Error("serveConfig returned no error when KURA_PII_DETECTOR_URL was unset")
	}
}

// With a complete environment, serveConfig produces a Config that New
// accepts — proof the wiring is complete.
func TestServeConfigWiresAcceptableConfig(t *testing.T) {
	env := serveEnv()
	cfg, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("serveConfig: %v", err)
	}
	if cfg.Addr != "127.0.0.1:8080" {
		t.Errorf("Addr = %q, want 127.0.0.1:8080", cfg.Addr)
	}
	if cfg.Auth == nil || cfg.Recorder == nil || cfg.Google == nil || cfg.Gate == nil {
		t.Error("serveConfig left a required enforcement collaborator nil")
	}
	if cfg.Trust.FirmDomain != "examplefirm.com" {
		t.Errorf("Trust.FirmDomain = %q, want examplefirm.com", cfg.Trust.FirmDomain)
	}
	if _, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] }); err != nil {
		t.Fatalf("serveConfig with a complete environment: %v", err)
	}
}

// `kura serve` is wired into the command tree as the real command, not
// the not-implemented stub. The stub carries no flags; the real command
// carries --addr, so the flag's presence proves the wiring.
func TestServeCommandIsWired(t *testing.T) {
	root := newRootCmd()
	serve, _, err := root.Find([]string{"serve"})
	if err != nil {
		t.Fatalf("finding serve command: %v", err)
	}
	if serve.Name() != "serve" {
		t.Fatalf("found command %q, want serve", serve.Name())
	}
	if serve.Flags().Lookup("addr") == nil {
		t.Fatal("serve in the command tree is still the not-implemented stub (no --addr flag)")
	}
}

// `kura serve` exposes an --addr flag so an operator can choose the bind
// address.
func TestServeCommandHasAddrFlag(t *testing.T) {
	addr := newServeCmd().Flags().Lookup("addr")
	if addr == nil {
		t.Fatal("serve command has no --addr flag")
	}
	if addr.DefValue == "" {
		t.Error("--addr flag has no default value")
	}
}
