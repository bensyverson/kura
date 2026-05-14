// Package db will own the Postgres connection and the forward-only
// migration runner (see internal/migrations). It is a placeholder at the
// skeleton stage; the Postgres layer lands in build-plan Phase 1.
//
// The blank import pins the project's chosen driver — pgx via the
// database/sql interface — as a deliberate, recorded dependency decision.
package db

import (
	_ "github.com/jackc/pgx/v5/stdlib"
)
