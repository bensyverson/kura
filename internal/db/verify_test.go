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

// After migration 0010, pgcrypto is dropped: field-level encryption moved to
// the application layer, so the extension must no longer be installed. This
// guards against a regression that re-introduces a database-level crypto
// dependency the erasable-key-store model deliberately removed.
func TestPgcryptoIsDropped(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	if err := Migrate(ctx, env.DB); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	st, err := extensionStatus(ctx, env.DB, "pgcrypto")
	if err != nil {
		t.Fatalf("extensionStatus(pgcrypto): %v", err)
	}
	if st.Installed {
		t.Error("pgcrypto is still installed after migration 0010; it must be dropped")
	}

	// gen_random_uuid still resolves to the core Postgres built-in, so UUID
	// primary-key defaults keep working with pgcrypto gone.
	var id string
	if err := env.DB.QueryRowContext(ctx, `SELECT gen_random_uuid()`).Scan(&id); err != nil {
		t.Fatalf("gen_random_uuid after dropping pgcrypto: %v", err)
	}
	if id == "" {
		t.Error("gen_random_uuid returned empty after dropping pgcrypto")
	}
}
