package server

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/bensyverson/kura/internal/identity"
)

// microsoftDirectoryIntegrationEnv collects the environment
// configuration the live-Graph integration test reads. The test runs
// only when every required variable is set; that keeps an unconfigured
// developer machine and CI from being asked to reach Microsoft.
type microsoftDirectoryIntegrationEnv struct {
	tenantID       string
	clientID       string
	clientSecret   string
	activeEmail    string
	suspendedEmail string
	absentEmail    string
}

func requireMicrosoftDirectoryEnv(t *testing.T) microsoftDirectoryIntegrationEnv {
	t.Helper()
	env := microsoftDirectoryIntegrationEnv{
		tenantID:       os.Getenv("KURA_MICROSOFT_DIRECTORY_TENANT_ID"),
		clientID:       os.Getenv("KURA_MICROSOFT_DIRECTORY_CLIENT_ID"),
		clientSecret:   os.Getenv("KURA_MICROSOFT_DIRECTORY_CLIENT_SECRET"),
		activeEmail:    os.Getenv("KURA_MICROSOFT_DIRECTORY_TEST_ACTIVE_EMAIL"),
		suspendedEmail: os.Getenv("KURA_MICROSOFT_DIRECTORY_TEST_SUSPENDED_EMAIL"),
		absentEmail:    os.Getenv("KURA_MICROSOFT_DIRECTORY_TEST_ABSENT_EMAIL"),
	}
	missing := []string{}
	if env.tenantID == "" {
		missing = append(missing, "KURA_MICROSOFT_DIRECTORY_TENANT_ID")
	}
	if env.clientID == "" {
		missing = append(missing, "KURA_MICROSOFT_DIRECTORY_CLIENT_ID")
	}
	if env.clientSecret == "" {
		missing = append(missing, "KURA_MICROSOFT_DIRECTORY_CLIENT_SECRET")
	}
	if env.activeEmail == "" {
		missing = append(missing, "KURA_MICROSOFT_DIRECTORY_TEST_ACTIVE_EMAIL")
	}
	if env.absentEmail == "" {
		missing = append(missing, "KURA_MICROSOFT_DIRECTORY_TEST_ABSENT_EMAIL")
	}
	if len(missing) > 0 {
		t.Skipf("integration test skipped — set %v to run against a live Entra tenant", missing)
	}
	return env
}

// The Microsoft Graph directory integration test exercises the real
// HTTP path against a live Entra tenant. It is skipped unless the
// operator opts in by setting the KURA_MICROSOFT_DIRECTORY_* env vars;
// it never runs by default.
func TestMicrosoftDirectoryAgainstLiveEntra(t *testing.T) {
	env := requireMicrosoftDirectoryEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dir, err := NewMicrosoftDirectory(ctx, MicrosoftDirectoryConfig{
		TenantID:     env.tenantID,
		ClientID:     env.clientID,
		ClientSecret: env.clientSecret,
	})
	if err != nil {
		t.Fatalf("NewMicrosoftDirectory: %v", err)
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
