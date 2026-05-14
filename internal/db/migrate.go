package db

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/bensyverson/kura/internal/migrations"
)

// schemaMigrationsDDL creates the runner's own bookkeeping table. It lives
// in public, not the kura schema: it is migration-runner infrastructure,
// not application data, and it must exist before migration 0001 creates
// the kura schema.
const schemaMigrationsDDL = `
CREATE TABLE IF NOT EXISTS public.schema_migrations (
    version    integer PRIMARY KEY,
    name       text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
)`

// Version returns the highest migration number applied to db, or 0 if no
// migrations have been applied yet. It is safe to call against a database
// the runner has never touched: it ensures the bookkeeping table exists.
func Version(ctx context.Context, db *sql.DB) (int, error) {
	if _, err := db.ExecContext(ctx, schemaMigrationsDDL); err != nil {
		return 0, fmt.Errorf("db: ensuring schema_migrations: %w", err)
	}
	var v sql.NullInt64
	if err := db.QueryRowContext(ctx,
		`SELECT max(version) FROM public.schema_migrations`).Scan(&v); err != nil {
		return 0, fmt.Errorf("db: reading schema version: %w", err)
	}
	return int(v.Int64), nil
}

// Migrate applies every pending migration to db in sequence order, each in
// its own transaction, recording the applied version in
// public.schema_migrations. It is idempotent: migrations already recorded
// are skipped, so an empty database is brought to the current schema and
// an up-to-date database is left untouched. This is the automatic runner
// the server invokes on startup; migrations are never applied by hand.
func Migrate(ctx context.Context, db *sql.DB) error {
	all, err := migrations.All()
	if err != nil {
		return err
	}
	current, err := Version(ctx, db)
	if err != nil {
		return err
	}
	for _, m := range all {
		if m.Number <= current {
			continue
		}
		if err := applyMigration(ctx, db, m); err != nil {
			return fmt.Errorf("db: applying migration %04d (%s): %w", m.Number, m.Name, err)
		}
	}
	return nil
}

// applyMigration runs one migration and records it, atomically: the schema
// change and its bookkeeping row commit together or not at all, so a
// half-applied migration can never be recorded as done.
func applyMigration(ctx context.Context, db *sql.DB, m migrations.Migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO public.schema_migrations (version, name) VALUES ($1, $2)`,
		m.Number, m.Name); err != nil {
		return err
	}
	return tx.Commit()
}
