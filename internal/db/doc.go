// Package db owns Kura's Postgres layer: TLS-required connections, the
// forward-only migration runner (over the SQL in internal/migrations),
// extension verification, and the pgcrypto-backed field-encryption
// primitives.
//
//   - Connections: ParseConfig / Open refuse any DSN that would permit a
//     non-TLS connection.
//   - Migrations: Migrate applies pending migrations on startup, each in
//     its own transaction, recording the version in
//     public.schema_migrations.
//   - Extensions: VerifyExtensions reports pgcrypto and pgaudit
//     availability, surfacing a pgaudit gap as a blocker.
//   - Encryption: EncryptValue / DecryptValue wrap pgcrypto under an
//     app-managed key from the secrets manager.
//
// The blank import pins the project's chosen driver — pgx via the
// database/sql interface — as a deliberate, recorded dependency decision.
package db

import (
	_ "github.com/jackc/pgx/v5/stdlib"
)
