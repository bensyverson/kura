package server

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/bensyverson/kura/internal/identity"
)

// googleDirectoryIntegrationEnv collects the environment configuration
// the integration test reads. The test runs only when every required
// variable is set; that keeps an unconfigured developer machine and CI
// from being asked to reach Google.
type googleDirectoryIntegrationEnv struct {
	credentialsFile string
	subject         string
	activeEmail     string
	suspendedEmail  string
	absentEmail     string
}

// requireGoogleDirectoryEnv loads the integration environment or skips
// the test. The active and absent emails are required (those are the
// two cases every Workspace tenant has); suspendedEmail is optional and
// activates an extra assertion when present.
func requireGoogleDirectoryEnv(t *testing.T) googleDirectoryIntegrationEnv {
	t.Helper()
	env := googleDirectoryIntegrationEnv{
		credentialsFile: os.Getenv("KURA_GOOGLE_DIRECTORY_CREDENTIALS"),
		subject:         os.Getenv("KURA_GOOGLE_DIRECTORY_SUBJECT"),
		activeEmail:     os.Getenv("KURA_GOOGLE_DIRECTORY_TEST_ACTIVE_EMAIL"),
		suspendedEmail:  os.Getenv("KURA_GOOGLE_DIRECTORY_TEST_SUSPENDED_EMAIL"),
		absentEmail:     os.Getenv("KURA_GOOGLE_DIRECTORY_TEST_ABSENT_EMAIL"),
	}
	missing := []string{}
	if env.credentialsFile == "" {
		missing = append(missing, "KURA_GOOGLE_DIRECTORY_CREDENTIALS")
	}
	if env.subject == "" {
		missing = append(missing, "KURA_GOOGLE_DIRECTORY_SUBJECT")
	}
	if env.activeEmail == "" {
		missing = append(missing, "KURA_GOOGLE_DIRECTORY_TEST_ACTIVE_EMAIL")
	}
	if env.absentEmail == "" {
		missing = append(missing, "KURA_GOOGLE_DIRECTORY_TEST_ABSENT_EMAIL")
	}
	if len(missing) > 0 {
		t.Skipf("integration test skipped — set %v to run against a live Workspace tenant", missing)
	}
	return env
}

// The Google Workspace directory integration test exercises the real
// Admin SDK against a live tenant: it builds the directory from a
// service-account key, then verifies the three status mappings —
// active, absent, and (optionally) suspended — that AccountStatus
// promises. It is skipped unless the operator opts in by setting the
// KURA_GOOGLE_DIRECTORY_* env vars; it never runs by default.
func TestGoogleDirectoryAgainstLiveWorkspace(t *testing.T) {
	env := requireGoogleDirectoryEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dir, err := NewGoogleDirectory(ctx, GoogleDirectoryConfig{
		CredentialsFile: env.credentialsFile,
		Subject:         env.subject,
	})
	if err != nil {
		t.Fatalf("NewGoogleDirectory: %v", err)
	}

	got, err := dir.AccountStatus(ctx, env.activeEmail)
	if err != nil {
		t.Fatalf("AccountStatus(active=%q): %v", env.activeEmail, err)
	}
	if got != identity.AccountActive {
		t.Errorf("AccountStatus(active=%q) = %q, want %q", env.activeEmail, got, identity.AccountActive)
	}

	got, err = dir.AccountStatus(ctx, env.absentEmail)
	if err != nil {
		t.Fatalf("AccountStatus(absent=%q): %v", env.absentEmail, err)
	}
	if got != identity.AccountAbsent {
		t.Errorf("AccountStatus(absent=%q) = %q, want %q", env.absentEmail, got, identity.AccountAbsent)
	}

	if env.suspendedEmail != "" {
		got, err = dir.AccountStatus(ctx, env.suspendedEmail)
		if err != nil {
			t.Fatalf("AccountStatus(suspended=%q): %v", env.suspendedEmail, err)
		}
		if got != identity.AccountSuspended {
			t.Errorf("AccountStatus(suspended=%q) = %q, want %q", env.suspendedEmail, got, identity.AccountSuspended)
		}
	}
}
