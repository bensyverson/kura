package data

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/bensyverson/kura/internal/crypto"
	"github.com/bensyverson/kura/internal/keystore"
	"github.com/jackc/pgx/v5/pgconn"
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
// values with per-field storage decisions, the PII spans detected at
// ingestion, and any relationship edges to other records. It is what the
// gate's Ingest hands the write seam after it has authorized, validated,
// scanned, and classified the record.
//
// Relationships are the edges declared for this record at creation; the
// writer persists them in the same tenant transaction as the record (see
// EdgeInput), so the record and its edges commit atomically.
type RecordInput struct {
	Entity        string
	Fields        []FieldInput
	Spans         []SpanInput
	Relationships []EdgeInput
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

	m.mu.Lock()
	defer m.mu.Unlock()
	// Referential integrity, mirroring the edges' foreign key: every target
	// must already exist. Checking before storing anything keeps the record
	// and its edges atomic — a bad edge leaves nothing behind.
	for _, e := range rec.Relationships {
		if !m.hasRecordLocked(e.TargetID) {
			return "", fmt.Errorf("%w: target %s", ErrEdgeTargetNotFound, e.TargetID)
		}
	}
	seq := m.putLocked(rec.Entity, Record{ID: id, Fields: fields})
	for _, e := range rec.Relationships {
		m.edges = append(m.edges, Edge{
			Relationship: e.Relationship,
			SourceID:     id,
			SourceSeq:    seq,
			TargetID:     e.TargetID,
		})
	}
	return id, nil
}

// Insert stores rec under its entity inside a tenant-scoped read-write
// transaction and returns the new record's id. Fields flagged Encrypted
// are sealed in Go under a fresh per-value DEK (see sealField); the rest
// go to value_text. Detected spans are written to kura.pii_spans. The
// record, its field values, and its spans commit together or not at all.
//
// Encrypted fields persist key-store-first: the wrapped DEK lands in the
// separate key store before the ciphertext is written. There is no
// cross-instance transaction, so this ordering ensures a mid-failure
// leaves at worst an orphan DEK (harmless, unused key material a later
// sweep can reclaim) rather than undecryptable ciphertext.
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
				ciphertext, err := s.sealField(ctx, id, f.Name, f.Value)
				if err != nil {
					return err
				}
				if _, err := tx.ExecContext(ctx,
					`INSERT INTO kura.record_field_values
					     (record_id, tenant_id, field_name, field_type, value_encrypted)
					 VALUES ($1, $2, $3, $4, $5)`,
					id, s.tenantID, f.Name, f.Type, ciphertext); err != nil {
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
		// Edges are written in this same transaction, so the record and its
		// edges commit together. The target's foreign key turns a reference
		// to a missing record into a typed ErrEdgeTargetNotFound rather than
		// a raw driver error, and rolls the whole insert back.
		for _, e := range rec.Relationships {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO kura.record_edges
				     (tenant_id, source_record_id, target_record_id, relationship)
				 VALUES ($1, $2, $3, $4)`,
				s.tenantID, id, e.TargetID, e.Relationship); err != nil {
				return mapEdgeTargetErr(err, e.TargetID)
			}
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("data: inserting record: %w", err)
	}
	return id, nil
}

// sealField encrypts value for the field named fieldName under a fresh
// per-value DEK, persists the wrapped DEK to the key store, and returns the
// ciphertext bytes for value_encrypted. It is the write half of the
// envelope: generate a DEK, seal the value with it (AES-256-GCM in Go),
// wrap the DEK under the master KEK, and store the wrapped DEK keyed by
// (tenant, record, field) — before the caller writes the ciphertext, so a
// failure never strands undecryptable ciphertext.
func (s *PostgresStore) sealField(ctx context.Context, recordID, fieldName, value string) ([]byte, error) {
	dek, err := crypto.GenerateDEK()
	if err != nil {
		return nil, fmt.Errorf("data: generating DEK for %q: %w", fieldName, err)
	}
	ciphertext, err := crypto.Encrypt(dek, []byte(value))
	if err != nil {
		return nil, fmt.Errorf("data: encrypting %q: %w", fieldName, err)
	}
	wrapped, err := s.wrapper.Wrap(dek)
	if err != nil {
		return nil, fmt.Errorf("data: wrapping DEK for %q: %w", fieldName, err)
	}
	if err := s.keys.Store(ctx, keystore.Key{
		TenantID:  s.tenantID,
		RecordID:  recordID,
		FieldName: fieldName,
	}, wrapped); err != nil {
		return nil, fmt.Errorf("data: storing wrapped DEK for %q: %w", fieldName, err)
	}
	return ciphertext, nil
}

// mapEdgeTargetErr turns the database's reaction to an edge naming a missing
// or malformed target into the typed ErrEdgeTargetNotFound: a foreign-key
// violation (23503) means no such record, and an invalid-uuid (22P02) target
// likewise cannot reference one. Any other error passes through unchanged.
func mapEdgeTargetErr(err error, targetID string) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && (pgErr.Code == "23503" || pgErr.Code == "22P02") {
		return fmt.Errorf("%w: target %s", ErrEdgeTargetNotFound, targetID)
	}
	return err
}
