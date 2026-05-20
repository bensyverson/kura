package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bensyverson/kura/internal/identity"
)

// testServiceAccountFile writes a service-account JSON with a freshly
// generated RSA key into t.TempDir() and returns the path. It is the
// minimum shape google.JWTConfigFromJSON accepts — enough that
// NewGoogleDirectory's construction succeeds without ever touching the
// network. The key never signs anything reachable in the tests; its
// only role is to make the JSON parseable.
func testServiceAccountFile(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	sa := map[string]string{
		"type":           "service_account",
		"project_id":     "kura-test",
		"private_key_id": "test-key-id",
		"private_key":    string(pemBytes),
		"client_email":   "kura-test@kura-test.iam.gserviceaccount.com",
		"client_id":      "0",
		"auth_uri":       "https://accounts.google.com/o/oauth2/auth",
		"token_uri":      "https://oauth2.googleapis.com/token",
	}
	data, err := json.Marshal(sa)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "service-account.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write service-account: %v", err)
	}
	return path
}

// With KURA_IDP=google, missing KURA_GOOGLE_DIRECTORY_CREDENTIALS must
// fail loudly: the Google directory cannot run without a service-account
// key, and IdP-mismatch detection on the Google path is exactly the
// feature this credentials file enables.
func TestServeConfigGoogleRequiresDirectoryCredentials(t *testing.T) {
	env := serveEnv(t)
	delete(env, "KURA_GOOGLE_DIRECTORY_CREDENTIALS")
	_, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] })
	if err == nil {
		t.Fatal("serveConfig accepted KURA_IDP=google with no KURA_GOOGLE_DIRECTORY_CREDENTIALS")
	}
	if !strings.Contains(err.Error(), "KURA_GOOGLE_DIRECTORY_CREDENTIALS") {
		t.Errorf("error %q does not name the missing variable", err)
	}
}

// With KURA_IDP=google, missing KURA_GOOGLE_DIRECTORY_SUBJECT must fail.
// The Admin SDK refuses anonymous calls; the operator-provided admin
// email is what the service account impersonates.
func TestServeConfigGoogleRequiresDirectorySubject(t *testing.T) {
	env := serveEnv(t)
	delete(env, "KURA_GOOGLE_DIRECTORY_SUBJECT")
	_, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] })
	if err == nil {
		t.Fatal("serveConfig accepted KURA_IDP=google with no KURA_GOOGLE_DIRECTORY_SUBJECT")
	}
	if !strings.Contains(err.Error(), "KURA_GOOGLE_DIRECTORY_SUBJECT") {
		t.Errorf("error %q does not name the missing variable", err)
	}
}

// With KURA_IDP=google and a valid service-account file + subject,
// serveConfig wires a real Directory (not the v1 FakeDirectory). The
// concrete type cannot be asserted from outside its package; we instead
// observe behavior — the real googleDirectory would attempt a Google
// API call and (against the test fake) return an error, where the
// FakeDirectory returns AccountAbsent for an unknown email. We use the
// converse: serveConfig must succeed, and IdP must be non-nil — the
// behavior assertion lives in the directory's own unit tests.
func TestServeConfigGoogleBuildsDirectory(t *testing.T) {
	env := serveEnv(t)
	cfg, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("serveConfig: %v", err)
	}
	if cfg.IdP == nil {
		t.Fatal("serveConfig left cfg.IdP nil — directory not wired")
	}
}

// KURA_DIRECTORY=none wires the noop directory regardless of the IdP, so
// a deployment without directory-API access (or a local dev instance) can
// opt out of IdP-mismatch detection. The noop directory reports every
// account active and never dials out.
func TestServeConfigDirectoryNoneWiresNoopDirectory(t *testing.T) {
	env := serveEnv(t)
	env["KURA_DIRECTORY"] = "none"
	// The google directory credentials must not be required on this path.
	delete(env, "KURA_GOOGLE_DIRECTORY_CREDENTIALS")
	delete(env, "KURA_GOOGLE_DIRECTORY_SUBJECT")

	cfg, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("serveConfig with KURA_DIRECTORY=none: %v", err)
	}
	if cfg.IdP == nil {
		t.Fatal("serveConfig left cfg.IdP nil")
	}
	got, err := cfg.IdP.AccountStatus(context.Background(), "anyone@anywhere.example")
	if err != nil {
		t.Fatalf("AccountStatus: %v", err)
	}
	if got != identity.AccountActive {
		t.Errorf("AccountStatus = %q, want %q (noop directory) — KURA_DIRECTORY=none did not select noop", got, identity.AccountActive)
	}
}

// With KURA_DIRECTORY=none, the Google directory env vars are not read, so
// their absence is not an error.
func TestServeConfigDirectoryNoneSkipsGoogleDirectoryVars(t *testing.T) {
	env := serveEnv(t)
	env["KURA_DIRECTORY"] = "none"
	delete(env, "KURA_GOOGLE_DIRECTORY_CREDENTIALS")
	delete(env, "KURA_GOOGLE_DIRECTORY_SUBJECT")
	if _, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] }); err != nil {
		if strings.Contains(err.Error(), "KURA_GOOGLE_DIRECTORY") {
			t.Errorf("KURA_DIRECTORY=none must not require Google directory vars: %v", err)
		}
	}
}

// With KURA_IDP=oidc, the directory must be the noop directory: it
// reports AccountActive for every email so the mismatch endpoint serves
// a consistent (empty) result rather than a transport error. Generic
// OIDC has no standard directory API.
func TestServeConfigOIDCWiresNoopDirectory(t *testing.T) {
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
		t.Fatalf("serveConfig: %v", err)
	}
	if cfg.IdP == nil {
		t.Fatal("serveConfig left cfg.IdP nil for KURA_IDP=oidc")
	}
	got, err := cfg.IdP.AccountStatus(context.Background(), "anyone@anywhere.example")
	if err != nil {
		t.Fatalf("AccountStatus: %v", err)
	}
	if got != identity.AccountActive {
		t.Errorf("AccountStatus for an unknown email = %q, want %q (noop directory) — wrong directory wired", got, identity.AccountActive)
	}
}

// With KURA_IDP=oidc, no Google directory env vars are required —
// a generic-OIDC deployment never reads them.
func TestServeConfigOIDCDoesNotRequireGoogleDirectoryVars(t *testing.T) {
	env := serveEnv(t)
	env["KURA_IDP"] = "oidc"
	delete(env, "KURA_GOOGLE_CLIENT_ID")
	delete(env, "KURA_GOOGLE_CLIENT_SECRET")

	disc := newDiscoveryServer(t)
	defer disc.Close()
	env["KURA_OIDC_ISSUER_URL"] = disc.URL
	env["KURA_OIDC_CLIENT_ID"] = "kura"
	env["KURA_OIDC_CLIENT_SECRET"] = "shh"

	if _, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] }); err != nil {
		if strings.Contains(err.Error(), "KURA_GOOGLE_DIRECTORY") {
			t.Errorf("KURA_IDP=oidc must not require Google directory vars: %v", err)
		}
	}
}

// With KURA_IDP=microsoft, no Google directory env vars are required —
// a Microsoft-only deployment never reads them. The Microsoft
// directory reuses the IdP's client creds, so no additional Microsoft
// env vars are required either.
func TestServeConfigMicrosoftDoesNotRequireGoogleDirectoryVars(t *testing.T) {
	env := serveEnv(t)
	env["KURA_IDP"] = "microsoft"
	delete(env, "KURA_GOOGLE_CLIENT_ID")
	delete(env, "KURA_GOOGLE_CLIENT_SECRET")
	env["KURA_MICROSOFT_TENANT_ID"] = "common"
	env["KURA_MICROSOFT_CLIENT_ID"] = "kura"
	env["KURA_MICROSOFT_CLIENT_SECRET"] = "shh"
	// Microsoft IdP discovery may fail offline (expected); what must
	// not appear is a Google-directory validation error.
	if _, err := serveConfig("127.0.0.1:8080", func(k string) string { return env[k] }); err != nil {
		if strings.Contains(err.Error(), "KURA_GOOGLE_DIRECTORY") {
			t.Errorf("Microsoft path required a Google directory env var: %v", err)
		}
	}
}
