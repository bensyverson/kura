package db

import (
	"context"
	"testing"
)

func TestVerifyExtensions(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	if err := Migrate(ctx, env.DB); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	r, err := VerifyExtensions(ctx, env.DB)
	if err != nil {
		t.Fatalf("VerifyExtensions: %v", err)
	}

	// pgcrypto is created by migration 0001 — it must be both available
	// and installed.
	if !r.Pgcrypto.Available {
		t.Error("pgcrypto is not available on the test server")
	}
	if !r.Pgcrypto.Installed {
		t.Error("pgcrypto is not installed; migration 0001 should have created it")
	}

	// pgaudit need only be available. The integration container bundles
	// it (mirroring DO Managed Postgres); if a server lacks it, the
	// blocker must be surfaced rather than passing silently.
	if !r.Pgaudit.Available {
		t.Errorf("pgaudit is not available; blocker surfaced: %q", r.Blocker())
	}

	if !r.OK() {
		t.Errorf("ExtensionReport not OK; blocker: %q", r.Blocker())
	}
	if r.OK() && r.Blocker() != "" {
		t.Errorf("report is OK but Blocker() = %q, want empty", r.Blocker())
	}
}
