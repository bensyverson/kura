package data

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/bensyverson/kura/internal/crypto"
	"github.com/bensyverson/kura/internal/keystore"
)

// ErrMissingDependency is returned by a Postgres store constructor when
// a required collaborator is missing. A store that cannot read or write
// safely — no pool, no tenant to scope RLS to, or no key material to
// encrypt with — must not come into existence.
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
//   - Field encryption. An encrypted field's value is sealed in Go with a
//     per-value DEK (crypto.Encrypt), the DEK wrapped under the master KEK
//     and persisted to the separate key store; the ciphertext bytes land in
//     value_encrypted. Reads reverse it: fetch and unwrap the DEK through
//     the cache, decrypt in Go. Per ADR 0002 the DEK lives in a physically
//     separate, erasable instance, so crypto runs in the application, never
//     as a SQL expression. A value whose DEK was shredded reads back as
//     erased (named in Record.Erased), never as ciphertext or an error.
type PostgresStore struct {
	db       *sql.DB
	tenantID string
	// keys persists wrapped DEKs on write; keyring seals a fresh DEK under
	// the active KEK generation (and reports that generation so the write is
	// stamped to match); cache fronts the key store on read, unwrapping DEKs
	// and honouring crypto-shred eviction. Writes go through keys+keyring,
	// reads through cache (which reads the same store), so a value written
	// here reads back through the cache.
	keys    keystore.KeyStore
	keyring *crypto.KeyRing
	cache   *keystore.Cache
}

var _ RecordStore = (*PostgresStore)(nil)

// NewPostgresStore returns a PostgresStore reading db, scoped to tenantID,
// encrypting field values under per-value DEKs. The pool should be
// connected as the RLS-bound kura_api role; the tenant id comes from
// deployment configuration. keys is the wrapped-DEK store, keyring the
// versioned KEK set (the write path seals under its active generation; its
// blast radius stays small — the store never holds the raw KEK), and cache
// the read-side unwrapping cache over the same store.
func NewPostgresStore(db *sql.DB, tenantID string, keys keystore.KeyStore, keyring *crypto.KeyRing, cache *keystore.Cache) (*PostgresStore, error) {
	if db == nil || tenantID == "" || keys == nil || keyring == nil || cache == nil {
		return nil, ErrMissingDependency
	}
	return &PostgresStore{db: db, tenantID: tenantID, keys: keys, keyring: keyring, cache: cache}, nil
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
		fields, erased, err := s.fieldsOf(ctx, tx, id)
		if err != nil {
			return err
		}
		rec = Record{ID: id, Seq: seq, Fields: fields, Erased: erased}
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
			fields, erased, err := s.fieldsOf(ctx, tx, k.id)
			if err != nil {
				return err
			}
			out = append(out, Record{ID: k.id, Seq: k.seq, Fields: fields, Erased: erased})
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

var _ EdgeReader = (*PostgresStore)(nil)

// EdgesByTarget returns every edge whose target is targetID, ordered by the
// source record's seq via a join to kura.records — "all records that point at
// this one, in order". RLS scopes the rows to the store's tenant.
func (s *PostgresStore) EdgesByTarget(ctx context.Context, targetID string) ([]Edge, error) {
	return s.queryEdges(ctx,
		`SELECT e.relationship, e.source_record_id::text, r.seq, e.target_record_id::text
		   FROM kura.record_edges e
		   JOIN kura.records r ON r.id = e.source_record_id
		  WHERE e.target_record_id::text = $1
		  ORDER BY r.seq`, targetID)
}

// EdgesBySource returns every edge originating from sourceID, ordered by the
// source record's seq for a stable result.
func (s *PostgresStore) EdgesBySource(ctx context.Context, sourceID string) ([]Edge, error) {
	return s.queryEdges(ctx,
		`SELECT e.relationship, e.source_record_id::text, r.seq, e.target_record_id::text
		   FROM kura.record_edges e
		   JOIN kura.records r ON r.id = e.source_record_id
		  WHERE e.source_record_id::text = $1
		  ORDER BY r.seq`, sourceID)
}

// queryEdges runs an edge query in a tenant-scoped read transaction. The
// endpoint id is compared as text so a malformed (non-uuid) argument simply
// matches nothing rather than erroring on the cast — the same defence Get
// uses for record ids.
func (s *PostgresStore) queryEdges(ctx context.Context, query, arg string) ([]Edge, error) {
	var out []Edge
	err := s.inTenantTx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, query, arg)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e Edge
			if err := rows.Scan(&e.Relationship, &e.SourceID, &e.SourceSeq, &e.TargetID); err != nil {
				return err
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// fieldsOf reads one record's field values, decrypting any stored
// encrypted with their per-value DEK. Plaintext (structural) fields come
// straight from value_text. For an encrypted field it fetches the DEK
// through the cache, unwraps it, and decrypts in Go.
//
// A field whose DEK has been crypto-shredded is not an error and not
// ciphertext: it is reported as erased — its name added to the returned
// erased list and omitted from fields — so a read of a partially erased
// record stays a normal, non-failing operation. A genuine authentication
// failure (tampering or a wrong KEK) stays a hard error, distinct from an
// erased value. A record with no field rows yields an empty, non-nil map
// and a nil erased list.
func (s *PostgresStore) fieldsOf(ctx context.Context, tx *sql.Tx, recordID string) (map[string]string, []string, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT field_name, value_text, value_encrypted
		 FROM kura.record_field_values WHERE record_id = $1`,
		recordID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	type encField struct {
		name       string
		ciphertext []byte
	}
	fields := make(map[string]string)
	var encrypted []encField
	for rows.Next() {
		var name string
		var text sql.NullString
		var ciphertext []byte
		if err := rows.Scan(&name, &text, &ciphertext); err != nil {
			return nil, nil, err
		}
		// exactly_one_value guarantees precisely one of value_text /
		// value_encrypted is non-NULL, so a NULL text is an encrypted field.
		if ciphertext == nil {
			fields[name] = text.String
			continue
		}
		encrypted = append(encrypted, encField{name: name, ciphertext: ciphertext})
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	var erased []string
	for _, ef := range encrypted {
		dek, found, err := s.cache.Unwrapped(ctx, keystore.Key{
			TenantID:  s.tenantID,
			RecordID:  recordID,
			FieldName: ef.name,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("data: unwrapping DEK for %q: %w", ef.name, err)
		}
		if !found {
			// The DEK is gone — crypto-shredded. The ciphertext is
			// permanently opaque by design; report the field as erased.
			erased = append(erased, ef.name)
			continue
		}
		plaintext, err := crypto.Decrypt(dek, ef.ciphertext)
		if err != nil {
			// A present DEK that cannot open the value means tampered
			// ciphertext or a wrong KEK — a hard error, never a silent miss.
			return nil, nil, fmt.Errorf("data: decrypting %q: %w", ef.name, err)
		}
		fields[ef.name] = string(plaintext)
	}
	return fields, erased, nil
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
