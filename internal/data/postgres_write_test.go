package data

import (
	"bytes"
	"context"
	"testing"

	"github.com/bensyverson/kura/internal/crypto"
	"github.com/bensyverson/kura/internal/keystore"
)

// PostgresStore satisfies the RecordWriter interface.
func TestPostgresStoreIsARecordWriter(t *testing.T) {
	var _ RecordWriter = (*PostgresStore)(nil)
}

// A record written through Insert reads back through Get with every field
// intact: plaintext fields verbatim, encrypted fields decrypted. The write
// runs as the RLS-bound kura_api role, so this also proves a tenant-scoped
// write satisfies the row-level-security WITH CHECK.
func TestPostgresStoreInsertRoundTrips(t *testing.T) {
	env := newDataTestEnv(t)
	ce := newCryptoEnv(t)
	tenant := newTenantID(t, env)
	store := newRecordStore(t, connectAsAPIRole(t, env), tenant, ce)

	id, err := store.Insert(context.Background(), RecordInput{
		Entity: "patient",
		Fields: []FieldInput{
			{Name: "full_name", Type: "string", Value: "Jane Doe"},
			{Name: "ssn", Type: "string", Value: "123-45-6789", Encrypted: true},
		},
	})
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if id == "" {
		t.Fatal("Insert returned an empty id")
	}

	rec, ok, err := store.Get(context.Background(), "patient", id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("Get: inserted record not found")
	}
	if rec.Fields["full_name"] != "Jane Doe" || rec.Fields["ssn"] != "123-45-6789" {
		t.Errorf("rec.Fields = %+v, want full_name + ssn round-tripped", rec.Fields)
	}
}

// The write path stamps the active KEK generation on the wrapped DEK it
// stores — taken from the key ring, not the old hardcoded default — so a
// value written while the active KEK is v7 is labelled v7, and a later
// rotation selects it correctly rather than trying the wrong key.
func TestPostgresStoreInsertStampsActiveKEKVersion(t *testing.T) {
	env := newDataTestEnv(t)
	ce := newCryptoEnvAtVersion(t, 7)
	tenant := newTenantID(t, env)
	store := newRecordStore(t, connectAsAPIRole(t, env), tenant, ce)

	id, err := store.Insert(context.Background(), RecordInput{
		Entity: "patient",
		Fields: []FieldInput{{Name: "ssn", Type: "string", Value: "123-45-6789", Encrypted: true}},
	})
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}
	v, ok := ce.Keys.Version(keystore.Key{TenantID: tenant, RecordID: id, FieldName: "ssn"})
	if !ok {
		t.Fatal("no wrapped DEK stored for the encrypted ssn field")
	}
	if v != 7 {
		t.Errorf("stored kek_version = %d, want 7 (the active generation, not a hardcoded default)", v)
	}
}

// An Insert field flagged Encrypted is genuinely ciphertext at rest, while
// a plaintext field lands in value_text. This is the write half of the
// encryption guarantee whose read half TestPostgresStoreDecryptsEncryptedFields
// covers.
func TestPostgresStoreInsertEncryptsFlaggedFieldsAtRest(t *testing.T) {
	env := newDataTestEnv(t)
	ce := newCryptoEnv(t)
	tenant := newTenantID(t, env)
	store := newRecordStore(t, connectAsAPIRole(t, env), tenant, ce)

	id, err := store.Insert(context.Background(), RecordInput{
		Entity: "patient",
		Fields: []FieldInput{
			{Name: "full_name", Type: "string", Value: "Jane Doe"},
			{Name: "ssn", Type: "string", Value: "123-45-6789", Encrypted: true},
		},
	})
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}

	raw := rawEncryptedValue(t, env, id, "ssn")
	if len(raw) == 0 {
		t.Fatal("ssn stored with an empty value_encrypted")
	}
	if bytes.Contains(raw, []byte("123-45-6789")) {
		t.Fatal("ssn ciphertext at rest contains the plaintext")
	}

	// The write is an envelope write: a wrapped DEK for the field landed in
	// the key store, keyed by (tenant, record, field). Without it the
	// ciphertext would be unrecoverable — so its presence is the write half
	// of crypto-shreddability.
	wrapped, _, found, err := ce.Keys.Fetch(context.Background(), keystore.Key{
		TenantID: tenant, RecordID: id, FieldName: "ssn",
	})
	if err != nil {
		t.Fatalf("keystore Fetch: %v", err)
	}
	if !found || len(wrapped) == 0 {
		t.Fatal("no wrapped DEK stored for the encrypted ssn field")
	}
	// The stored key is wrapped, not the raw DEK: unwrapping it must
	// succeed and yield a 32-byte AES-256 DEK.
	dek, err := ce.Wrapper.Unwrap(wrapped)
	if err != nil {
		t.Fatalf("unwrapping stored DEK: %v", err)
	}
	if len(dek) != crypto.DEKSize {
		t.Errorf("unwrapped DEK is %d bytes, want %d", len(dek), crypto.DEKSize)
	}

	// The plaintext field is stored in value_text, not encrypted.
	var text string
	var encNull bool
	err = env.DB.QueryRow(
		`SELECT value_text, value_encrypted IS NULL
		   FROM kura.record_field_values
		  WHERE record_id = $1 AND field_name = 'full_name'`, id).Scan(&text, &encNull)
	if err != nil {
		t.Fatalf("reading full_name row: %v", err)
	}
	if text != "Jane Doe" || !encNull {
		t.Errorf("full_name stored as value_text=%q value_encrypted-is-null=%v, want plaintext", text, encNull)
	}
}

// Detected-PII spans handed to Insert are persisted to kura.pii_spans as
// ingestion metadata — coordinates only, never the text. This is the read
// trail the access-review and analysis surfaces will draw on.
func TestPostgresStoreInsertPersistsSpans(t *testing.T) {
	env := newDataTestEnv(t)
	ce := newCryptoEnv(t)
	tenant := newTenantID(t, env)
	store := newRecordStore(t, connectAsAPIRole(t, env), tenant, ce)

	id, err := store.Insert(context.Background(), RecordInput{
		Entity: "patient",
		Fields: []FieldInput{{Name: "notes", Type: "text", Value: "call John Roe", Encrypted: true}},
		Spans: []SpanInput{
			{Field: "notes", Category: "private_person", Offset: 5, Length: 8, Confidence: 0.91},
		},
	})
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}

	var category string
	var offset, length int
	var confidence float64
	err = env.DB.QueryRow(
		`SELECT category, byte_offset, byte_length, confidence
		   FROM kura.pii_spans WHERE record_id = $1 AND field_name = 'notes'`, id).
		Scan(&category, &offset, &length, &confidence)
	if err != nil {
		t.Fatalf("reading pii_spans row: %v", err)
	}
	if category != "private_person" || offset != 5 || length != 8 {
		t.Errorf("span = {category:%q offset:%d length:%d}, want {private_person 5 8}", category, offset, length)
	}
}
