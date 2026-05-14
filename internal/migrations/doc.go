// Package migrations holds the forward-only SQL migrations for Kura's
// Postgres schema. Migration files are numbered with an incrementing
// leading number and are never edited once committed; schema changes are
// always a new migration.
//
// An automatic migration runner applies pending migrations on server
// startup and records the current migration number in the database —
// migrations are never run by hand. The runner lives in internal/db
// (db.Migrate); this package embeds the SQL and exposes it as an ordered,
// contiguously numbered list via All.
package migrations
