package data

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrMissingDependency is returned by a Postgres store constructor when
// a required collaborator is missing. A store that cannot read or write
// safely — no pool, or no tenant to scope RLS to — must not come into
// existence.
var ErrMissingDependency = errors.New("data: postgres store is missing a required dependency")

// PostgresStore is the production RecordStore: it assembles records from
// the kura.records / kura.record_field_values EAV tables. It is
// enforcement-blind in the same way MemStore is — it returns raw field
// values and leaves authorization and masking to the gate — but it does
// own two storage-layer concerns the schema demands:
//
//   - Tenant isolation. Every read runs inside a transaction that sets
//     the kura.tenant_id GUC, so the row-level-security policies bind. A
//     store scoped to one tenant cannot see another's rows, even though
//     the table is physically shared.
//
//   - Field decryption. A field stored encrypted (value_encrypted, for
//     high-sensitivity and free-text values) is decrypted with the
//     app-managed key as part of the read query. The store hands back
//     plaintext; the bytes at rest stay ciphertext.
type PostgresStore struct {
	db       *sql.DB
	tenantID string
	encKey   string
}

var _ RecordStore = (*PostgresStore)(nil)

// NewPostgresStore returns a PostgresStore reading db, scoped to
// tenantID, decrypting with encryptionKey. The pool should be connected
// as the RLS-bound kura_api role; the tenant id and key come from
// deployment configuration and the secrets manager.
func NewPostgresStore(db *sql.DB, tenantID, encryptionKey string) (*PostgresStore, error) {
	if db == nil || tenantID == "" || encryptionKey == "" {
		return nil, ErrMissingDependency
	}
	return &PostgresStore{db: db, tenantID: tenantID, encKey: encryptionKey}, nil
}

// Get returns the record with the given id under entity. A missing
// record — absent, a malformed id, or one carrying a different entity —
// is reported as ok == false with a nil error, never as a failure.
func (s *PostgresStore) Get(ctx context.Context, entity, id string) (Record, bool, error) {
	var (
		rec   Record
		found bool
	)
	err := s.inTenantTx(ctx, func(tx *sql.Tx) error {
		// id is compared as text so a malformed (non-uuid) id simply
		// matches nothing, rather than erroring on the uuid cast. RLS
		// has already scoped the visible rows to this tenant. The record's
		// seq comes back here so the read carries its order key.
		var seq int64
		switch err := tx.QueryRowContext(ctx,
			`SELECT seq FROM kura.records WHERE id::text = $1 AND entity = $2`,
			id, entity).Scan(&seq); {
		case errors.Is(err, sql.ErrNoRows):
			return nil
		case err != nil:
			return err
		}
		found = true
		fields, err := s.fieldsOf(ctx, tx, id)
		if err != nil {
			return err
		}
		rec = Record{ID: id, Seq: seq, Fields: fields}
		return nil
	})
	if err != nil {
		return Record{}, false, err
	}
	return rec, found, nil
}

// List returns a bounded, stably ordered page of entity's records. The
// gate has already clamped limit and offset; the store reads what it is
// asked for. Records are ordered by creation time, then id, so the
// ordering is total and pagination over it is well-defined.
func (s *PostgresStore) List(ctx context.Context, entity string, limit, offset int) ([]Record, error) {
	var out []Record
	err := s.inTenantTx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx,
			`SELECT id::text, seq FROM kura.records
			 WHERE entity = $1 ORDER BY created_at, id LIMIT $2 OFFSET $3`,
			entity, limit, offset)
		if err != nil {
			return err
		}
		type rowKey struct {
			id  string
			seq int64
		}
		var keys []rowKey
		for rows.Next() {
			var k rowKey
			if err := rows.Scan(&k.id, &k.seq); err != nil {
				rows.Close()
				return err
			}
			keys = append(keys, k)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()

		for _, k := range keys {
			fields, err := s.fieldsOf(ctx, tx, k.id)
			if err != nil {
				return err
			}
			out = append(out, Record{ID: k.id, Seq: k.seq, Fields: fields})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Count returns the number of entity's records visible to the store's
// tenant. RLS scopes the count the same way it scopes Get and List, so a
// store sees only its own tenant's rows.
func (s *PostgresStore) Count(ctx context.Context, entity string) (int, error) {
	var n int
	err := s.inTenantTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT count(*) FROM kura.records WHERE entity = $1`, entity).Scan(&n)
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// fieldsOf reads one record's field values, decrypting any that were
// stored encrypted. A record with no field rows yields an empty,
// non-nil map.
func (s *PostgresStore) fieldsOf(ctx context.Context, tx *sql.Tx, recordID string) (map[string]string, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT field_name,
		        CASE WHEN value_encrypted IS NULL
		             THEN value_text
		             ELSE pgp_sym_decrypt(value_encrypted, $2) END
		 FROM kura.record_field_values WHERE record_id = $1`,
		recordID, s.encKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	fields := make(map[string]string)
	for rows.Next() {
		var name, value string
		if err := rows.Scan(&name, &value); err != nil {
			return nil, err
		}
		fields[name] = value
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return fields, nil
}

// inTenantTx runs fn inside a read-only transaction scoped to the
// store's tenant.
func (s *PostgresStore) inTenantTx(ctx context.Context, fn func(*sql.Tx) error) error {
	return withTenantTx(ctx, s.db, s.tenantID, true, fn)
}

// withTenantTx runs fn inside a transaction with the kura.tenant_id GUC
// set to tenantID. set_config's third argument is true — the setting is
// transaction-local — so it cannot leak onto another pooled
// connection's later use. RLS keys on this GUC, so without it a
// connection sees nothing; with it, exactly one tenant's rows. readOnly
// chooses the transaction mode: reads use a read-only transaction,
// writes a read-write one that is committed when fn succeeds.
func withTenantTx(ctx context.Context, db *sql.DB, tenantID string, readOnly bool, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: readOnly})
	if err != nil {
		return fmt.Errorf("data: begin transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx,
		`SELECT set_config('kura.tenant_id', $1, true)`, tenantID); err != nil {
		return fmt.Errorf("data: setting tenant scope: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}
