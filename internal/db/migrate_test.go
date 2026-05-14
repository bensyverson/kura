package db

import (
	"context"
	"testing"

	"github.com/bensyverson/kura/internal/migrations"
)

func TestMigrateAppliesEmptyToCurrent(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)

	v, err := Version(ctx, env.DB)
	if err != nil {
		t.Fatalf("Version on fresh database: %v", err)
	}
	if v != 0 {
		t.Fatalf("fresh database Version = %d, want 0", v)
	}

	if err := Migrate(ctx, env.DB); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	all, err := migrations.All()
	if err != nil {
		t.Fatal(err)
	}
	want := all[len(all)-1].Number

	v, err = Version(ctx, env.DB)
	if err != nil {
		t.Fatalf("Version after Migrate: %v", err)
	}
	if v != want {
		t.Fatalf("after Migrate, Version = %d, want %d", v, want)
	}

	// Idempotent: a second run against an up-to-date database is a no-op.
	if err := Migrate(ctx, env.DB); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	v, err = Version(ctx, env.DB)
	if err != nil {
		t.Fatal(err)
	}
	if v != want {
		t.Fatalf("after second Migrate, Version = %d, want %d", v, want)
	}

	// The schema is really there: the kura schema has its tables.
	var tables int
	if err := env.DB.QueryRowContext(ctx,
		`SELECT count(*) FROM information_schema.tables WHERE table_schema = 'kura'`).
		Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if tables == 0 {
		t.Fatal("kura schema has no tables after Migrate")
	}

	// Every applied migration is recorded with its name.
	var recorded int
	if err := env.DB.QueryRowContext(ctx,
		`SELECT count(*) FROM public.schema_migrations`).Scan(&recorded); err != nil {
		t.Fatal(err)
	}
	if recorded != len(all) {
		t.Fatalf("schema_migrations has %d rows, want %d", recorded, len(all))
	}
}
