package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrEmptyEncryptionKey is returned when a field-encryption operation is
// given an empty key. The key is supplied by the secrets manager; an empty
// key means a misconfiguration, and encrypting under it would be a silent
// security failure.
var ErrEmptyEncryptionKey = errors.New("db: encryption key is empty")

// EncryptValue encrypts plaintext under key using pgcrypto's
// pgp_sym_encrypt and returns ciphertext suitable for a bytea column. This
// is Kura's field-level encryption primitive: high-sensitivity field
// values and free-text column values are stored as the output of this
// function, never as plaintext. The key is app-managed and comes from the
// secrets manager — it is never written to the database.
func EncryptValue(ctx context.Context, db *sql.DB, key, plaintext string) ([]byte, error) {
	if key == "" {
		return nil, ErrEmptyEncryptionKey
	}
	var ciphertext []byte
	if err := db.QueryRowContext(ctx,
		`SELECT pgp_sym_encrypt($1, $2)`, plaintext, key).Scan(&ciphertext); err != nil {
		return nil, fmt.Errorf("db: encrypting value: %w", err)
	}
	return ciphertext, nil
}

// DecryptValue reverses EncryptValue: it decrypts ciphertext produced by
// pgp_sym_encrypt under the same key. A wrong key fails loudly rather than
// returning garbage.
func DecryptValue(ctx context.Context, db *sql.DB, key string, ciphertext []byte) (string, error) {
	if key == "" {
		return "", ErrEmptyEncryptionKey
	}
	var plaintext string
	if err := db.QueryRowContext(ctx,
		`SELECT pgp_sym_decrypt($1, $2)`, ciphertext, key).Scan(&plaintext); err != nil {
		return "", fmt.Errorf("db: decrypting value: %w", err)
	}
	return plaintext, nil
}
