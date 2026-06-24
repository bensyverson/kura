package keystore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrMissingPool is returned when a Postgres key store is constructed
// without a database pool. A store that cannot reach the key-store instance
// must not come into existence.
var ErrMissingPool = errors.New("keystore: postgres store needs a database pool")

// PostgresStore is the production KeyStore, backed by the separate,
// erasable key-store Postgres instance (ADR 0002). It is multi-tenant: each
// operation scopes itself to its key's tenant, both by setting the
// kura.tenant_id GUC the RLS policy binds to and by filtering on tenant_id
// in SQL, so tenant isolation holds even on a connection that bypasses RLS.
type PostgresStore struct {
	db *sql.DB
}

var _ KeyStore = (*PostgresStore)(nil)

// NewPostgresStore returns a KeyStore reading and writing the key-store
// instance behind db. The pool should connect as the key store's
// RLS-scoped runtime role.
func NewPostgresStore(db *sql.DB) (*PostgresStore, error) {
	if db == nil {
		return nil, ErrMissingPool
	}
	return &PostgresStore{db: db}, nil
}

// Store persists the wrapped DEK for key's field value.
func (s *PostgresStore) Store(ctx context.Context, key Key, wrappedDEK []byte) error {
	if !key.complete() {
		return ErrIncompleteKey
	}
	return s.inTenantTx(ctx, key.TenantID, false, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO kura.wrapped_deks (tenant_id, record_id, field_name, wrapped_dek)
			 VALUES ($1, $2, $3, $4)`,
			key.TenantID, key.RecordID, key.FieldName, wrappedDEK)
		return err
	})
}

// Fetch returns the wrapped DEK for key, or a clean miss if it was never
// stored or has been shredded. A malformed (non-uuid) record id matches
// nothing and reads as a miss rather than erroring, mirroring the record
// store's tolerance.
func (s *PostgresStore) Fetch(ctx context.Context, key Key) ([]byte, bool, error) {
	var wrapped []byte
	found := false
	err := s.inTenantTx(ctx, key.TenantID, true, func(tx *sql.Tx) error {
		switch err := tx.QueryRowContext(ctx,
			`SELECT wrapped_dek FROM kura.wrapped_deks
			 WHERE tenant_id::text = $1 AND record_id::text = $2 AND field_name = $3`,
			key.TenantID, key.RecordID, key.FieldName).Scan(&wrapped); {
		case errors.Is(err, sql.ErrNoRows):
			return nil
		case err != nil:
			return err
		}
		found = true
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	if !found {
		return nil, false, nil
	}
	return wrapped, true, nil
}

// Shred deletes every wrapped DEK for the given records within tenantID,
// returning how many were deleted. This is the crypto-shred: the affected
// values' ciphertext becomes permanently undecryptable. An empty record set
// is a no-op.
func (s *PostgresStore) Shred(ctx context.Context, tenantID string, recordIDs []string) (int, error) {
	if len(recordIDs) == 0 {
		return 0, nil
	}
	var deleted int64
	err := s.inTenantTx(ctx, tenantID, false, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`DELETE FROM kura.wrapped_deks
			 WHERE tenant_id::text = $1 AND record_id::text = ANY($2)`,
			tenantID, recordIDs)
		if err != nil {
			return err
		}
		deleted, err = res.RowsAffected()
		return err
	})
	if err != nil {
		return 0, err
	}
	return int(deleted), nil
}

// inTenantTx runs fn inside a transaction scoped to tenantID via the
// kura.tenant_id GUC (transaction-local, so it cannot leak onto another
// pooled connection). It mirrors the record store's tenant-tx helper; the
// key store enforces the same isolation as the main database.
func (s *PostgresStore) inTenantTx(ctx context.Context, tenantID string, readOnly bool, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: readOnly})
	if err != nil {
		return fmt.Errorf("keystore: begin transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx,
		`SELECT set_config('kura.tenant_id', $1, true)`, tenantID); err != nil {
		return fmt.Errorf("keystore: setting tenant scope: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}
