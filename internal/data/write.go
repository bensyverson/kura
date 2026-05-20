package data

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
)

// FieldInput is one field to persist, carrying the storage decisions the
// ingestion path made for it: its manifest type (for the field_type
// column), its value, and whether the value must be stored encrypted at
// rest. A field is stored encrypted xor plaintext — the schema's
// exactly_one_value constraint admits no third state.
type FieldInput struct {
	Name      string
	Type      string
	Value     string
	Encrypted bool
}

// SpanInput is one detected-PII span to persist as ingestion metadata in
// kura.pii_spans. The coordinates are byte positions into the source
// field's text; the text itself is never copied here.
type SpanInput struct {
	Field      string
	Category   string
	Offset     int
	Length     int
	Confidence float64
}

// RecordInput is a complete record to persist: its entity, its field
// values with per-field storage decisions, and the PII spans detected at
// ingestion. It is what the gate's Ingest hands the write seam after it
// has authorized, validated, scanned, and classified the record.
type RecordInput struct {
	Entity string
	Fields []FieldInput
	Spans  []SpanInput
}

// RecordWriter persists records. It is the write seam beneath the gate's
// Ingest, deliberately separate from the read-only RecordStore: a read
// seam should not grow writes (and a write seam should not grow reads).
// Insert returns the new record's id.
type RecordWriter interface {
	Insert(ctx context.Context, rec RecordInput) (string, error)
}

// newRecordID mints a random 128-bit id, hex-encoded — the in-memory
// store's stand-in for the database's gen_random_uuid default, matching
// how the jobs and review memory stores generate ids.
func newRecordID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("data: generating record id: %w", err)
	}
	return hex.EncodeToString(buf[:]), nil
}

// Insert stores rec under its entity and returns the new record's id. The
// in-memory store has no at-rest representation, so the per-field
// Encrypted flags and the spans are not materialized — it stores the field
// values verbatim, exactly as they read back. It exists so adapters and
// tests can exercise the write path without a database.
func (m *MemStore) Insert(_ context.Context, rec RecordInput) (string, error) {
	id, err := newRecordID()
	if err != nil {
		return "", err
	}
	fields := make(map[string]string, len(rec.Fields))
	for _, f := range rec.Fields {
		fields[f.Name] = f.Value
	}
	m.Put(rec.Entity, Record{ID: id, Fields: fields})
	return id, nil
}

// Insert stores rec under its entity inside a tenant-scoped read-write
// transaction and returns the new record's id. Fields flagged Encrypted
// are written to value_encrypted via pgp_sym_encrypt under the store's
// key; the rest go to value_text. Detected spans are written to
// kura.pii_spans. The record, its field values, and its spans commit
// together or not at all.
func (s *PostgresStore) Insert(ctx context.Context, rec RecordInput) (string, error) {
	var id string
	err := withTenantTx(ctx, s.db, s.tenantID, false, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx,
			`INSERT INTO kura.records (tenant_id, entity) VALUES ($1, $2) RETURNING id::text`,
			s.tenantID, rec.Entity).Scan(&id); err != nil {
			return err
		}
		for _, f := range rec.Fields {
			if f.Encrypted {
				if _, err := tx.ExecContext(ctx,
					`INSERT INTO kura.record_field_values
					     (record_id, tenant_id, field_name, field_type, value_encrypted)
					 VALUES ($1, $2, $3, $4, pgp_sym_encrypt($5, $6))`,
					id, s.tenantID, f.Name, f.Type, f.Value, s.encKey); err != nil {
					return err
				}
				continue
			}
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO kura.record_field_values
				     (record_id, tenant_id, field_name, field_type, value_text)
				 VALUES ($1, $2, $3, $4, $5)`,
				id, s.tenantID, f.Name, f.Type, f.Value); err != nil {
				return err
			}
		}
		for _, sp := range rec.Spans {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO kura.pii_spans
				     (record_id, tenant_id, field_name, category, byte_offset, byte_length, confidence)
				 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
				id, s.tenantID, sp.Field, sp.Category, sp.Offset, sp.Length, sp.Confidence); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("data: inserting record: %w", err)
	}
	return id, nil
}
