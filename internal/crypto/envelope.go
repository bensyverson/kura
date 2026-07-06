// Package crypto is Kura's application-layer envelope-encryption primitives.
//
// It replaces the in-database pgcrypto path (internal/db/crypto.go): per
// ADR 0002, data-encryption keys (DEKs) live in a physically separate,
// erasable key store, so they are unreachable from a SQL expression in the
// main database. Crypto must therefore run in Go, with the DEK in hand.
//
// The functions here are pure: they take key material as arguments and
// touch no database and no environment. That keeps them exhaustively
// unit-testable and auditable, and keeps key blast-radius decisions (where
// the KEK lives, how DEKs are cached) out of the cryptography itself.
//
// Two layers, the same primitive (AES-256-GCM) applied at different scopes:
//
//   - Encrypt/Decrypt protect a field value under a per-value DEK.
//   - WrapDEK/UnwrapDEK protect a DEK under the master KEK.
//
// GCM gives authenticated encryption, so a wrong key — wrong DEK on a value,
// wrong KEK on a wrapped DEK — fails authentication (ErrAuthentication)
// rather than returning plausible garbage.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// DEKSize is the length in bytes of a data-encryption key and of the master
// KEK: 32 bytes, mandating AES-256. Both value encryption and DEK wrapping
// use this size; a key of any other length is rejected as a
// misconfiguration rather than silently downgrading the cipher.
const DEKSize = 32

var (
	// ErrInvalidKeySize is returned when a key is not DEKSize bytes. AES-256
	// is mandatory; a 16- or 24-byte key is a configuration error, not an
	// invitation to use a weaker cipher.
	ErrInvalidKeySize = errors.New("crypto: key must be 32 bytes (AES-256)")

	// ErrAuthentication is returned when GCM authentication fails: the wrong
	// key, tampered ciphertext, or a corrupted nonce/tag. It never means the
	// plaintext was recovered — authenticated decryption returns nothing on
	// failure. Callers distinguishing a tampered value from a deliberately
	// shredded one (see rp-tombstone) match on this sentinel.
	ErrAuthentication = errors.New("crypto: authentication failed")
)

// GenerateDEK returns a fresh random 256-bit data-encryption key drawn from
// crypto/rand. Each encrypted field value gets its own DEK so that erasure
// can destroy exactly one value's key.
func GenerateDEK() ([]byte, error) {
	dek := make([]byte, DEKSize)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("crypto: generating DEK: %w", err)
	}
	return dek, nil
}

// Encrypt seals plaintext under key using AES-256-GCM with a fresh random
// nonce, returning nonce||ciphertext||tag. A random nonce makes encryption
// non-deterministic: identical plaintexts yield distinct ciphertexts, so
// nothing can be inferred by comparing stored values.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("crypto: generating nonce: %w", err)
	}
	// Seal appends the ciphertext+tag to the nonce, so the nonce is carried
	// in-band as the prefix and recovered by Decrypt.
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt reverses Encrypt: it splits the nonce prefix from sealed,
// authenticates, and returns the plaintext. A wrong key, tampered
// ciphertext, or truncated input returns ErrAuthentication (or, for input
// shorter than a nonce, an error) — never partial or garbage plaintext.
func Decrypt(key, sealed []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(sealed) < ns {
		return nil, fmt.Errorf("crypto: ciphertext too short: %d bytes", len(sealed))
	}
	nonce, ciphertext := sealed[:ns], sealed[ns:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrAuthentication
	}
	return plaintext, nil
}

// WrapDEK encrypts a DEK under the master KEK with AES-256-GCM, returning
// the wrapped DEK that the key store persists. It is the same authenticated
// primitive as Encrypt, applied to key material rather than a field value.
func WrapDEK(kek, dek []byte) ([]byte, error) {
	if len(dek) != DEKSize {
		return nil, fmt.Errorf("%w: DEK is %d bytes", ErrInvalidKeySize, len(dek))
	}
	return Encrypt(kek, dek)
}

// UnwrapDEK recovers the raw DEK from a wrapped DEK using the master KEK. A
// wrong KEK fails authentication (ErrAuthentication) rather than returning a
// garbage key that would then silently mis-decrypt every value.
func UnwrapDEK(kek, wrapped []byte) ([]byte, error) {
	return Decrypt(kek, wrapped)
}

// newGCM constructs an AES-256-GCM AEAD from key, enforcing the 32-byte key
// size up front so every entry point rejects an under-sized key identically.
func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != DEKSize {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidKeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: gcm: %w", err)
	}
	return gcm, nil
}
