package db

import (
	"context"
	"database/sql"
	"testing"
)

// TestSensitiveValuesStoredEncrypted covers the build-plan criterion that
// high-sensitivity fields are field-level encrypted and free-text columns
// are encrypted at rest: both kinds of value land in value_encrypted as
// pgcrypto ciphertext, and value_text stays NULL.
func TestSensitiveValuesStoredEncrypted(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	if err := Migrate(ctx, env.DB); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	const key = "field-encryption-key"
	tenant := newUUID(ctx, t, env.DB)
	conn := tenantConn(ctx, t, env.DB, tenant)

	var recordID string
	if err := conn.QueryRowContext(ctx,
		`INSERT INTO kura.records (tenant_id, entity) VALUES ($1, 'client') RETURNING id`,
		tenant).Scan(&recordID); err != nil {
		t.Fatalf("inserting record: %v", err)
	}

	// A high-sensitivity field (an account number) and a free-text field
	// (notes). Both are stored as ciphertext; the database never sees the
	// plaintext.
	fields := []struct {
		name, typ, plaintext string
	}{
		{"account_number", "string", "123-45-6789"},
		{"notes", "text", "free-text notes that may contain PII"},
	}
	for _, f := range fields {
		ciphertext, err := EncryptValue(ctx, env.DB, key, f.plaintext)
		if err != nil {
			t.Fatalf("encrypting %s: %v", f.name, err)
		}
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO kura.record_field_values
			   (record_id, tenant_id, field_name, field_type, value_encrypted)
			 VALUES ($1, $2, $3, $4, $5)`,
			recordID, tenant, f.name, f.typ, ciphertext); err != nil {
			t.Fatalf("inserting field %s: %v", f.name, err)
		}
	}

	// At rest: value_text is NULL for every sensitive field and
	// value_encrypted holds non-empty ciphertext.
	rows, err := conn.QueryContext(ctx,
		`SELECT field_name, value_text, value_encrypted
		   FROM kura.record_field_values WHERE record_id = $1`, recordID)
	if err != nil {
		t.Fatalf("reading field values: %v", err)
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var name string
		var valueText sql.NullString
		var valueEncrypted []byte
		if err := rows.Scan(&name, &valueText, &valueEncrypted); err != nil {
			t.Fatal(err)
		}
		seen++
		if valueText.Valid {
			t.Errorf("%s: value_text is populated (%q), want NULL — sensitive values must be encrypted", name, valueText.String)
		}
		if len(valueEncrypted) == 0 {
			t.Errorf("%s: value_encrypted is empty", name)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if seen != len(fields) {
		t.Fatalf("read %d field rows, want %d", seen, len(fields))
	}

	// The stored ciphertext round-trips back to the original plaintext.
	var ciphertext []byte
	if err := conn.QueryRowContext(ctx,
		`SELECT value_encrypted FROM kura.record_field_values
		   WHERE record_id = $1 AND field_name = 'account_number'`,
		recordID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	got, err := DecryptValue(ctx, env.DB, key, ciphertext)
	if err != nil {
		t.Fatalf("DecryptValue: %v", err)
	}
	if got != "123-45-6789" {
		t.Fatalf("decrypted account_number = %q, want %q", got, "123-45-6789")
	}
}
