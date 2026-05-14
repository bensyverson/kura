package db

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
)

// ErrInsecureDSN is returned when a DSN would permit a non-TLS connection
// to Postgres. 03-for-agents.md requires TLS on all database connections;
// non-TLS connections are refused.
var ErrInsecureDSN = errors.New("db: DSN permits a non-TLS connection; TLS is required")

// ParseConfig parses dsn into a Postgres connection config, rejecting any
// DSN that would permit a non-TLS connection. It accepts both URL-style
// and keyword-style DSNs.
func ParseConfig(dsn string) (*pgconn.Config, error) {
	cfg, err := pgconn.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("db: parsing DSN: %w", err)
	}
	if err := requireTLS(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Open parses and validates dsn — refusing any non-TLS DSN — then opens a
// database/sql pool backed by pgx. The pgx stdlib driver is registered by
// the blank import in doc.go.
func Open(dsn string) (*sql.DB, error) {
	if _, err := ParseConfig(dsn); err != nil {
		return nil, err
	}
	return sql.Open("pgx", dsn)
}

// requireTLS reports ErrInsecureDSN if cfg leaves any non-TLS connection
// path open. pgx models sslmode as a primary attempt plus ordered
// fallbacks: sslmode=disable produces a plaintext primary with no
// fallback, while allow and prefer leave a plaintext path as either the
// primary or a fallback. Only require/verify-ca/verify-full produce a
// config with TLS on every path.
func requireTLS(cfg *pgconn.Config) error {
	if cfg.TLSConfig == nil {
		return ErrInsecureDSN
	}
	for _, fb := range cfg.Fallbacks {
		if fb.TLSConfig == nil {
			return ErrInsecureDSN
		}
	}
	return nil
}
