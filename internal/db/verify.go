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

// ExtensionReport is the result of VerifyExtensions: the status of the
// extension Kura's database layer requires — pgaudit for forensic query
// logging. Field-level encryption no longer needs a database extension: it
// runs in the application layer (internal/crypto), so pgcrypto is gone (see
// migration 0010).
type ExtensionReport struct {
	Pgaudit ExtensionStatus
}

// OK reports whether the extension requirements are met. pgaudit need only
// be available: whether it actually loads depends on the server's
// shared_preload_libraries, a deployment setting outside any migration's
// reach.
func (r ExtensionReport) OK() bool {
	return r.Pgaudit.Available
}

// Blocker returns a human-readable description of the unmet extension
// requirement, or "" when OK. It is how the database layer surfaces a
// pgaudit gap rather than letting it pass silently.
func (r ExtensionReport) Blocker() string {
	if !r.Pgaudit.Available {
		return "pgaudit is not available on this Postgres server; forensic query logging cannot be enabled — the deployment's Postgres image or managed-database version must provide it"
	}
	return ""
}

// VerifyExtensions inspects the server and reports the availability and
// installed state of pgaudit.
func VerifyExtensions(ctx context.Context, db *sql.DB) (ExtensionReport, error) {
	pgaudit, err := extensionStatus(ctx, db, "pgaudit")
	if err != nil {
		return ExtensionReport{}, err
	}
	return ExtensionReport{Pgaudit: pgaudit}, nil
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
