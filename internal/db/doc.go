// Package db owns Kura's Postgres layer: TLS-required connections, the
// forward-only migration runner (over the SQL in internal/migrations), and
// extension verification.
//
//   - Connections: ParseConfig / Open refuse any DSN that would permit a
//     non-TLS connection.
//   - Migrations: Migrate applies the main pending migrations on startup and
//     MigrateKeystore the separate key-store lineage, each migration in its
//     own transaction, recording the version in public.schema_migrations.
//   - Extensions: VerifyExtensions reports pgaudit availability, surfacing a
//     pgaudit gap as a blocker.
//
// Field-level encryption is no longer a database concern: it runs in the
// application layer (internal/crypto) over per-value DEKs held in the
// separate key store (internal/keystore), so pgcrypto has been dropped
// (migration 0010).
//
// The blank import pins the project's chosen driver — pgx via the
// database/sql interface — as a deliberate, recorded dependency decision.
package db

import (
	_ "github.com/jackc/pgx/v5/stdlib"
)
