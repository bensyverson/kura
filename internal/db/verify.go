package db

import (
	"context"
	"database/sql"
	"fmt"
)

// ExtensionStatus reports whether a Postgres extension can be installed on
// the server and whether it is currently installed in this database.
type ExtensionStatus struct {
	Name      string
	Available bool // present in pg_available_extensions — CREATE EXTENSION can succeed
	Installed bool // present in pg_extension — already created in this database
}

// ExtensionReport is the result of VerifyExtensions: the status of the two
// extensions Kura's database layer requires — pgcrypto for field-level
// encryption, pgaudit for forensic query logging.
type ExtensionReport struct {
	Pgcrypto ExtensionStatus
	Pgaudit  ExtensionStatus
}

// OK reports whether the extension requirements are met. pgcrypto must be
// installed — migration 0001 creates it, and field-level encryption cannot
// work without it. pgaudit need only be available: whether it actually
// loads depends on the server's shared_preload_libraries, a deployment
// setting outside any migration's reach.
func (r ExtensionReport) OK() bool {
	return r.Pgcrypto.Available && r.Pgcrypto.Installed && r.Pgaudit.Available
}

// Blocker returns a human-readable description of the unmet extension
// requirement, or "" when OK. It is how the database layer surfaces a
// pgaudit gap rather than letting it pass silently.
func (r ExtensionReport) Blocker() string {
	switch {
	case !r.Pgcrypto.Available:
		return "pgcrypto is not available on this Postgres server; field-level encryption cannot function"
	case !r.Pgcrypto.Installed:
		return "pgcrypto is available but not installed; migration 0001 should have created it"
	case !r.Pgaudit.Available:
		return "pgaudit is not available on this Postgres server; forensic query logging cannot be enabled — the deployment's Postgres image or managed-database version must provide it"
	default:
		return ""
	}
}

// VerifyExtensions inspects the server and reports the availability and
// installed state of pgcrypto and pgaudit.
func VerifyExtensions(ctx context.Context, db *sql.DB) (ExtensionReport, error) {
	pgcrypto, err := extensionStatus(ctx, db, "pgcrypto")
	if err != nil {
		return ExtensionReport{}, err
	}
	pgaudit, err := extensionStatus(ctx, db, "pgaudit")
	if err != nil {
		return ExtensionReport{}, err
	}
	return ExtensionReport{Pgcrypto: pgcrypto, Pgaudit: pgaudit}, nil
}

func extensionStatus(ctx context.Context, db *sql.DB, name string) (ExtensionStatus, error) {
	st := ExtensionStatus{Name: name}
	err := db.QueryRowContext(ctx,
		`SELECT
		   EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = $1),
		   EXISTS (SELECT 1 FROM pg_extension WHERE extname = $1)`,
		name).Scan(&st.Available, &st.Installed)
	if err != nil {
		return ExtensionStatus{}, fmt.Errorf("db: checking extension %q: %w", name, err)
	}
	return st, nil
}
