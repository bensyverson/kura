package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bensyverson/kura/internal/data"
	"github.com/bensyverson/kura/internal/server"
)

// writeManifest writes content to a temp file and returns its path, for
// tests that drive serveConfig's KURA_MANIFEST_PATH loading.
func writeManifest(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing manifest: %v", err)
	}
	return path
}

// oneEntityManifest is a minimal valid manifest with a single entity, used
// to prove serveConfig loads it and the server grows the matching routes.
const oneEntityManifest = `{
  "version": "1",
  "entities": [
    {
      "name": "customer",
      "description": "A person whose data the client holds.",
      "fields": [
        { "name": "id", "type": "string", "description": "Stable identifier." },
        { "name": "full_name", "type": "string", "description": "Name.", "pii": "private_person" }
      ]
    }
  ]
}`

// serveEnv is a complete set of the environment variables serveConfig
// requires, for tests to start from and then perturb. It includes the
// optional LLM-gateway variables so the baseline produces a working
// gateway, and a per-test service-account JSON file so the default
// KURA_IDP=google directory wiring is complete; tests that care about
// the absence of any variable delete it.
func serveEnv(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{
		"KURA_SIGNING_SECRET":               "a-test-signing-secret",
		"KURA_IDP":                          "google",
		"KURA_GOOGLE_CLIENT_ID":             "client-id.apps.googleusercontent.com",
		"KURA_GOOGLE_CLIENT_SECRET":         "google-client-secret",
		"KURA_GOOGLE_DIRECTORY_CREDENTIALS": testServiceAccountFile(t),
		"KURA_GOOGLE_DIRECTORY_SUBJECT":     "admin@examplefirm.com",
		"KURA_PUBLIC_URL":                   "https://kura.client.example",
		"KURA_FIRM_DOMAIN":                  "examplefirm.com",
		"KURA_PII_DETECTOR_URL":             "http://127.0.0.1:9100/detect",
		"KURA_CLIENT_DOMAINS":               "client.example",
		"KURA_ADMIN_EMAILS":                 "boss@client.example",
		"KURA_ANTHROPIC_API_KEY":            "sk-ant-test-key",
		"KURA_ANTHROPIC_DPA_ON_FILE":        "true",
	}
}

// serveConfig must fail loudly when a required secret is absent — a
// server with no signing secret cannot mint or verify a token, and must
// not start.
func TestServeConfigRequiresSigningSecret(t *testing.T) {
	env := serveEnv(t)
	delete(env, "KURA_SIGNING_SECRET")
	if _, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] }); err == nil {
		t.Error("serveConfig returned no error when KURA_SIGNING_SECRET was unset")
	}
}

// serveConfig must fail when the Google OAuth client credentials are
// absent — kura serve cannot broker sign-in without them.
func TestServeConfigRequiresGoogleCredentials(t *testing.T) {
	env := serveEnv(t)
	delete(env, "KURA_GOOGLE_CLIENT_ID")
	if _, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] }); err == nil {
		t.Error("serveConfig returned no error when KURA_GOOGLE_CLIENT_ID was unset")
	}
}

// serveConfig must fail when the PII detector URL is absent — the gate
// cannot mask without a detector, and a server whose gate cannot mask
// must not start.
func TestServeConfigRequiresDetectorURL(t *testing.T) {
	env := serveEnv(t)
	delete(env, "KURA_PII_DETECTOR_URL")
	if _, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] }); err == nil {
		t.Error("serveConfig returned no error when KURA_PII_DETECTOR_URL was unset")
	}
}

// With a complete environment, serveConfig produces a Config that New
// accepts — proof the wiring is complete.
func TestServeConfigWiresAcceptableConfig(t *testing.T) {
	env := serveEnv(t)
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

// With no KURA_DATABASE_URL, serveConfig falls back to the in-memory
// stores — the credential-less dev/bare path. Existing behavior is
// unchanged: the record store and user store are MemStore/MemUserStore.
func TestServeConfigDefaultsToInMemoryStores(t *testing.T) {
	env := serveEnv(t)
	delete(env, "KURA_DATABASE_URL")
	cfg, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("serveConfig: %v", err)
	}
	if _, ok := cfg.Records.(*data.MemStore); !ok {
		t.Errorf("Records = %T, want *data.MemStore when no KURA_DATABASE_URL is set", cfg.Records)
	}
	if _, ok := cfg.Users.(*data.MemUserStore); !ok {
		t.Errorf("Users = %T, want *data.MemUserStore when no KURA_DATABASE_URL is set", cfg.Users)
	}
}

// With KURA_DATABASE_URL set, the tenant id is required: a Postgres store
// cannot scope its row-level-security to a tenant it has not been given,
// so startup must fail loudly rather than serve unscoped.
func TestServeConfigDatabaseURLRequiresTenantID(t *testing.T) {
	env := serveEnv(t)
	env["KURA_DATABASE_URL"] = "postgres://localhost:5432/kura?sslmode=require"
	env["KURA_RECORD_ENCRYPTION_KEY"] = "test-encryption-key"
	delete(env, "KURA_DB_TENANT_ID")
	_, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] })
	if err == nil {
		t.Fatal("serveConfig accepted KURA_DATABASE_URL with no KURA_DB_TENANT_ID")
	}
	if !strings.Contains(err.Error(), "KURA_DB_TENANT_ID") {
		t.Errorf("error %q does not name the missing variable", err)
	}
}

// With KURA_DATABASE_URL set, the record encryption key is required: the
// Postgres store decrypts encrypted fields with it, so a deployment that
// configures a database but no key must fail startup.
func TestServeConfigDatabaseURLRequiresEncryptionKey(t *testing.T) {
	env := serveEnv(t)
	env["KURA_DATABASE_URL"] = "postgres://localhost:5432/kura?sslmode=require"
	env["KURA_DB_TENANT_ID"] = "11111111-1111-1111-1111-111111111111"
	delete(env, "KURA_RECORD_ENCRYPTION_KEY")
	_, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] })
	if err == nil {
		t.Fatal("serveConfig accepted KURA_DATABASE_URL with no KURA_RECORD_ENCRYPTION_KEY")
	}
	if !strings.Contains(err.Error(), "KURA_RECORD_ENCRYPTION_KEY") {
		t.Errorf("error %q does not name the missing variable", err)
	}
}

// A KURA_DATABASE_URL that would permit a non-TLS connection must be
// rejected at startup — 03-for-agents.md requires TLS on every database
// connection. The rejection happens before any connection is attempted.
func TestServeConfigRejectsInsecureDatabaseURL(t *testing.T) {
	env := serveEnv(t)
	env["KURA_DATABASE_URL"] = "postgres://localhost:5432/kura?sslmode=disable"
	env["KURA_DB_TENANT_ID"] = "11111111-1111-1111-1111-111111111111"
	env["KURA_RECORD_ENCRYPTION_KEY"] = "test-encryption-key"
	_, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] })
	if err == nil {
		t.Fatal("serveConfig accepted a non-TLS KURA_DATABASE_URL")
	}
}

// With no KURA_MANIFEST_PATH, the gate runs on an empty manifest — the
// bare dev case. No entities means no data routes are generated, which is
// valid: a server can come up before a deployment has authored a schema.
func TestServeConfigEmptyManifestByDefault(t *testing.T) {
	env := serveEnv(t)
	delete(env, "KURA_MANIFEST_PATH")
	cfg, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("serveConfig: %v", err)
	}
	if got := len(cfg.Gate.Manifest().Entities); got != 0 {
		t.Errorf("Gate.Manifest().Entities = %d, want 0 with no KURA_MANIFEST_PATH", got)
	}
}

// With KURA_MANIFEST_PATH set, serveConfig loads the manifest through the
// Phase 1 parser, the gate carries its entities, and the server grows the
// matching data routes — proof the overview/data-browser have something to
// show.
func TestServeConfigLoadsManifestFromPath(t *testing.T) {
	env := serveEnv(t)
	env["KURA_MANIFEST_PATH"] = writeManifest(t, oneEntityManifest)
	cfg, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("serveConfig: %v", err)
	}
	ents := cfg.Gate.Manifest().Entities
	if len(ents) != 1 || ents[0].Name != "customer" {
		t.Fatalf("Gate.Manifest().Entities = %+v, want one 'customer' entity", ents)
	}
	// The route is a function of the manifest: with the entity loaded, the
	// server must route /api/customer/{id}. An unauthenticated request is
	// rejected (not 200), but a generated route is reached — never a 404,
	// which is what an unloaded manifest would produce.
	srv, err := server.New(cfg)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/customer/some-id", nil))
	if rec.Code == http.StatusNotFound {
		t.Errorf("GET /api/customer/some-id returned 404 — the manifest entity's data route was not generated")
	}
}

// An invalid manifest must fail startup loudly: the Cedar policy is built
// from the manifest, so a manifest that does not parse or validate cannot
// produce a safe policy, and the server must refuse to start rather than
// serve an unintended one.
func TestServeConfigRejectsInvalidManifest(t *testing.T) {
	env := serveEnv(t)
	env["KURA_MANIFEST_PATH"] = writeManifest(t, `{"version":"1","entities":[{"name":""}]}`)
	_, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] })
	if err == nil {
		t.Fatal("serveConfig accepted an invalid manifest — startup must fail loudly")
	}
	if !strings.Contains(err.Error(), "manifest") {
		t.Errorf("error %q does not mention the manifest", err)
	}
}

// A KURA_MANIFEST_PATH that points at no file must fail startup: an
// operator who misconfigures the path should see a loud error, not a
// silent fall-through to an empty schema.
func TestServeConfigRejectsMissingManifestFile(t *testing.T) {
	env := serveEnv(t)
	env["KURA_MANIFEST_PATH"] = filepath.Join(t.TempDir(), "does-not-exist.json")
	_, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] })
	if err == nil {
		t.Fatal("serveConfig accepted a KURA_MANIFEST_PATH pointing at no file")
	}
	if !strings.Contains(err.Error(), "manifest") {
		t.Errorf("error %q does not mention the manifest", err)
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
	env := serveEnv(t)
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
	env := serveEnv(t)
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
	env := serveEnv(t)
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

// KURA_IDP is required: a deployment that has not picked an identity
// provider must fail startup loudly rather than fall through to a
// default. A typo in the selector would otherwise silently change who
// can sign in.
func TestServeConfigRequiresKURA_IDP(t *testing.T) {
	env := serveEnv(t)
	delete(env, "KURA_IDP")
	_, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] })
	if err == nil {
		t.Fatal("serveConfig accepted an unset KURA_IDP — must require an explicit selector")
	}
	if !strings.Contains(err.Error(), "KURA_IDP") {
		t.Errorf("error %q does not name KURA_IDP", err)
	}
}

// With KURA_IDP=google, serveConfig wires the Google IdP — explicit form
// of the default.
func TestServeConfigSelectsGoogleIdP(t *testing.T) {
	env := serveEnv(t)
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
	env := serveEnv(t)
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
	env := serveEnv(t)
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
	env := serveEnv(t)
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
	env := serveEnv(t)
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
	env := serveEnv(t)
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
	env := serveEnv(t)
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

// With KURA_IDP=microsoft, missing KURA_MICROSOFT_TENANT_ID must fail
// before any network discovery is attempted.
func TestServeConfigMicrosoftRequiresTenantID(t *testing.T) {
	env := serveEnv(t)
	env["KURA_IDP"] = "microsoft"
	env["KURA_MICROSOFT_CLIENT_ID"] = "kura"
	env["KURA_MICROSOFT_CLIENT_SECRET"] = "shh"
	_, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] })
	if err == nil {
		t.Fatal("serveConfig accepted KURA_IDP=microsoft with no KURA_MICROSOFT_TENANT_ID")
	}
	if !strings.Contains(err.Error(), "KURA_MICROSOFT_TENANT_ID") {
		t.Errorf("error %q does not name the missing variable", err)
	}
}

// With KURA_IDP=microsoft, missing KURA_MICROSOFT_CLIENT_ID must fail.
func TestServeConfigMicrosoftRequiresClientID(t *testing.T) {
	env := serveEnv(t)
	env["KURA_IDP"] = "microsoft"
	env["KURA_MICROSOFT_TENANT_ID"] = "common"
	env["KURA_MICROSOFT_CLIENT_SECRET"] = "shh"
	_, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] })
	if err == nil {
		t.Fatal("serveConfig accepted KURA_IDP=microsoft with no KURA_MICROSOFT_CLIENT_ID")
	}
	if !strings.Contains(err.Error(), "KURA_MICROSOFT_CLIENT_ID") {
		t.Errorf("error %q does not name the missing variable", err)
	}
}

// With KURA_IDP=microsoft, missing KURA_MICROSOFT_CLIENT_SECRET must fail.
func TestServeConfigMicrosoftRequiresClientSecret(t *testing.T) {
	env := serveEnv(t)
	env["KURA_IDP"] = "microsoft"
	env["KURA_MICROSOFT_TENANT_ID"] = "common"
	env["KURA_MICROSOFT_CLIENT_ID"] = "kura"
	_, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] })
	if err == nil {
		t.Fatal("serveConfig accepted KURA_IDP=microsoft with no KURA_MICROSOFT_CLIENT_SECRET")
	}
	if !strings.Contains(err.Error(), "KURA_MICROSOFT_CLIENT_SECRET") {
		t.Errorf("error %q does not name the missing variable", err)
	}
}

// With KURA_IDP=microsoft, the Google and OIDC client credentials are
// not required — a Microsoft-only deployment must boot without ever
// setting them.
func TestServeConfigMicrosoftDoesNotRequireOtherIdPVars(t *testing.T) {
	env := serveEnv(t)
	env["KURA_IDP"] = "microsoft"
	delete(env, "KURA_GOOGLE_CLIENT_ID")
	delete(env, "KURA_GOOGLE_CLIENT_SECRET")
	env["KURA_MICROSOFT_TENANT_ID"] = "common"
	env["KURA_MICROSOFT_CLIENT_ID"] = "kura"
	env["KURA_MICROSOFT_CLIENT_SECRET"] = "shh"
	// We cannot complete construction without reaching the real Entra
	// discovery endpoint, so a non-network error here means the config
	// surface accepted Microsoft on its own. The discovery error is
	// expected when offline; the validation errors are not.
	_, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] })
	if err != nil {
		msg := err.Error()
		// Validation errors mention the env var names; a discovery
		// error mentions "discovery" or the issuer URL.
		if strings.Contains(msg, "KURA_GOOGLE") || strings.Contains(msg, "KURA_OIDC") {
			t.Errorf("Microsoft path required a non-Microsoft env var: %v", err)
		}
	}
}

// KURA_OAUTH_REDIRECT_URL, when set, overrides the default redirect
// URL derived from KURA_PUBLIC_URL. The override flows through to the
// IdP, so the consent-screen URL carries the operator-chosen
// redirect_uri.
func TestServeConfigOAuthRedirectURLOverride(t *testing.T) {
	env := serveEnv(t)
	env["KURA_OAUTH_REDIRECT_URL"] = "https://gateway.example/proxy/oauth/callback"
	cfg, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("serveConfig: %v", err)
	}
	authURL := cfg.Google.AuthCodeURL("state")
	if !strings.Contains(authURL, "redirect_uri=https%3A%2F%2Fgateway.example%2Fproxy%2Foauth%2Fcallback") {
		t.Errorf("AuthCodeURL = %q does not carry the overridden redirect_uri", authURL)
	}
}

// With KURA_OAUTH_REDIRECT_URL unset, the redirect URL is derived from
// KURA_PUBLIC_URL — the existing default — so an operator who does not
// terminate at a non-Kura path does not have to set it.
func TestServeConfigOAuthRedirectURLDefault(t *testing.T) {
	env := serveEnv(t)
	delete(env, "KURA_OAUTH_REDIRECT_URL")
	cfg, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("serveConfig: %v", err)
	}
	authURL := cfg.Google.AuthCodeURL("state")
	if !strings.Contains(authURL, "redirect_uri=https%3A%2F%2Fkura.client.example%2Foauth%2Fcallback") {
		t.Errorf("AuthCodeURL = %q does not derive redirect_uri from KURA_PUBLIC_URL", authURL)
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
