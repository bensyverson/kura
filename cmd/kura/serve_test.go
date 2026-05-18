package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// serveEnv is a complete set of the environment variables serveConfig
// requires, for tests to start from and then perturb. It includes the
// optional LLM-gateway variables so the baseline produces a working
// gateway; tests that care about its absence delete them.
func serveEnv() map[string]string {
	return map[string]string{
		"KURA_SIGNING_SECRET":        "a-test-signing-secret",
		"KURA_GOOGLE_CLIENT_ID":      "client-id.apps.googleusercontent.com",
		"KURA_GOOGLE_CLIENT_SECRET":  "google-client-secret",
		"KURA_PUBLIC_URL":            "https://kura.client.example",
		"KURA_FIRM_DOMAIN":           "examplefirm.com",
		"KURA_PII_DETECTOR_URL":      "http://127.0.0.1:9100/detect",
		"KURA_CLIENT_DOMAINS":        "client.example",
		"KURA_ADMIN_EMAILS":          "boss@client.example",
		"KURA_ANTHROPIC_API_KEY":     "sk-ant-test-key",
		"KURA_ANTHROPIC_DPA_ON_FILE": "true",
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
	if cfg.Trust.FirmTenant != "examplefirm.com" {
		t.Errorf("Trust.FirmTenant = %q, want examplefirm.com", cfg.Trust.FirmTenant)
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

// With the API key present and the DPA attested on file, serveConfig
// builds a working LLM gateway — the /api/llm endpoint will serve.
func TestServeConfigBuildsLLMGatewayWhenDPAOnFile(t *testing.T) {
	env := serveEnv()
	cfg, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("serveConfig: %v", err)
	}
	if cfg.LLM == nil {
		t.Error("serveConfig built no LLM gateway when the API key and DPA attestation were both present")
	}
}

// When the DPA is not attested on file, the startup DPA check fails:
// serveConfig still produces a usable Config — the server runs — but
// leaves the LLM gateway nil, so the /api/llm endpoint refuses to serve.
func TestServeConfigLeavesLLMGatewayNilWhenDPANotOnFile(t *testing.T) {
	env := serveEnv()
	delete(env, "KURA_ANTHROPIC_DPA_ON_FILE")
	cfg, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("serveConfig must still succeed without a DPA on file: %v", err)
	}
	if cfg.LLM != nil {
		t.Error("serveConfig built an LLM gateway when the DPA was not on file — the startup check must fail closed")
	}
}

// With no Anthropic API key there is no provider to broker, so there is
// no gateway — the endpoint refuses to serve, like the DPA-failed case.
func TestServeConfigLeavesLLMGatewayNilWithoutAPIKey(t *testing.T) {
	env := serveEnv()
	delete(env, "KURA_ANTHROPIC_API_KEY")
	cfg, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("serveConfig must still succeed without an LLM API key: %v", err)
	}
	if cfg.LLM != nil {
		t.Error("serveConfig built an LLM gateway with no API key")
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

// With KURA_IDP unset, serveConfig defaults to the Google IdP — the
// existing behavior must continue to work without an explicit selector.
func TestServeConfigDefaultsToGoogleIdP(t *testing.T) {
	env := serveEnv()
	delete(env, "KURA_IDP")
	cfg, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("serveConfig with KURA_IDP unset: %v", err)
	}
	if cfg.Google == nil {
		t.Error("serveConfig did not populate the IdP for the default selector")
	}
}

// With KURA_IDP=google, serveConfig wires the Google IdP — explicit form
// of the default.
func TestServeConfigSelectsGoogleIdP(t *testing.T) {
	env := serveEnv()
	env["KURA_IDP"] = "google"
	cfg, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("serveConfig with KURA_IDP=google: %v", err)
	}
	if cfg.Google == nil {
		t.Error("serveConfig with KURA_IDP=google did not populate the IdP")
	}
}

// An unrecognized KURA_IDP value must fail loudly. A typo here would
// otherwise silently fall back to a default and serve a sign-in flow
// the operator did not intend.
func TestServeConfigRejectsUnknownIdP(t *testing.T) {
	env := serveEnv()
	env["KURA_IDP"] = "banana"
	_, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] })
	if err == nil {
		t.Fatal("serveConfig accepted KURA_IDP=banana — must reject unknown identity providers")
	}
	if !strings.Contains(err.Error(), "KURA_IDP") {
		t.Errorf("error %q does not mention KURA_IDP — operator will not know why it failed", err)
	}
}

// With KURA_IDP=oidc, the generic-OIDC env vars take over: missing
// KURA_OIDC_ISSUER_URL must fail before any network discovery is
// attempted, so the operator sees a config error rather than a hung
// startup.
func TestServeConfigOIDCRequiresIssuerURL(t *testing.T) {
	env := serveEnv()
	env["KURA_IDP"] = "oidc"
	env["KURA_OIDC_CLIENT_ID"] = "kura"
	env["KURA_OIDC_CLIENT_SECRET"] = "shh"
	_, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] })
	if err == nil {
		t.Fatal("serveConfig accepted KURA_IDP=oidc with no KURA_OIDC_ISSUER_URL")
	}
	if !strings.Contains(err.Error(), "KURA_OIDC_ISSUER_URL") {
		t.Errorf("error %q does not name the missing variable", err)
	}
}

// With KURA_IDP=oidc, missing KURA_OIDC_CLIENT_ID must fail.
func TestServeConfigOIDCRequiresClientID(t *testing.T) {
	env := serveEnv()
	env["KURA_IDP"] = "oidc"
	env["KURA_OIDC_ISSUER_URL"] = "https://issuer.example/"
	env["KURA_OIDC_CLIENT_SECRET"] = "shh"
	_, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] })
	if err == nil {
		t.Fatal("serveConfig accepted KURA_IDP=oidc with no KURA_OIDC_CLIENT_ID")
	}
	if !strings.Contains(err.Error(), "KURA_OIDC_CLIENT_ID") {
		t.Errorf("error %q does not name the missing variable", err)
	}
}

// With KURA_IDP=oidc, missing KURA_OIDC_CLIENT_SECRET must fail.
func TestServeConfigOIDCRequiresClientSecret(t *testing.T) {
	env := serveEnv()
	env["KURA_IDP"] = "oidc"
	env["KURA_OIDC_ISSUER_URL"] = "https://issuer.example/"
	env["KURA_OIDC_CLIENT_ID"] = "kura"
	_, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] })
	if err == nil {
		t.Fatal("serveConfig accepted KURA_IDP=oidc with no KURA_OIDC_CLIENT_SECRET")
	}
	if !strings.Contains(err.Error(), "KURA_OIDC_CLIENT_SECRET") {
		t.Errorf("error %q does not name the missing variable", err)
	}
}

// With KURA_IDP=oidc, the Google client credentials are not required —
// a deployment that signs in via OIDC must be able to run without ever
// touching the Google environment variables.
func TestServeConfigOIDCDoesNotRequireGoogleVars(t *testing.T) {
	env := serveEnv()
	env["KURA_IDP"] = "oidc"
	delete(env, "KURA_GOOGLE_CLIENT_ID")
	delete(env, "KURA_GOOGLE_CLIENT_SECRET")

	disc := newDiscoveryServer(t)
	defer disc.Close()

	env["KURA_OIDC_ISSUER_URL"] = disc.URL
	env["KURA_OIDC_CLIENT_ID"] = "kura"
	env["KURA_OIDC_CLIENT_SECRET"] = "shh"

	cfg, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("serveConfig with KURA_IDP=oidc must not require Google vars: %v", err)
	}
	if cfg.Google == nil {
		t.Error("serveConfig with KURA_IDP=oidc left the IdP unpopulated")
	}
}

// With KURA_IDP=oidc and a reachable, well-formed discovery document,
// serveConfig builds a working IdP. The Config it returns must be one
// server.New accepts, just like the Google path.
func TestServeConfigOIDCBuildsIdP(t *testing.T) {
	env := serveEnv()
	env["KURA_IDP"] = "oidc"

	disc := newDiscoveryServer(t)
	defer disc.Close()

	env["KURA_OIDC_ISSUER_URL"] = disc.URL
	env["KURA_OIDC_CLIENT_ID"] = "kura"
	env["KURA_OIDC_CLIENT_SECRET"] = "shh"

	cfg, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("serveConfig with KURA_IDP=oidc: %v", err)
	}
	if cfg.Google == nil {
		t.Fatal("serveConfig with KURA_IDP=oidc did not populate the IdP")
	}
	// Prove the OIDC IdP was wired, not the Google one: its AuthCodeURL
	// must point at the discovery server's authorization endpoint.
	authURL := cfg.Google.AuthCodeURL("state")
	if !strings.HasPrefix(authURL, disc.URL+"/auth") {
		t.Errorf("AuthCodeURL = %q, expected to begin with %q — wrong IdP wired", authURL, disc.URL+"/auth")
	}
}

// newDiscoveryServer stands up an in-process OIDC discovery endpoint
// that issues just enough metadata for go-oidc's provider construction
// to succeed. It is the seam that lets the OIDC path of serveConfig be
// unit-tested without reaching a real Zitadel or Keycloak.
func newDiscoveryServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var base string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                base,
			"authorization_endpoint":                base + "/auth",
			"token_endpoint":                        base + "/token",
			"jwks_uri":                              base + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	})
	srv := httptest.NewServer(mux)
	base = srv.URL
	return srv
}
