// Package keystore is the seam between Kura's data layer and the erasable
// store of wrapped data-encryption keys.
//
// Per ADR 0002 the wrapped DEKs live in a physically separate, erasable
// Postgres instance — never beside the ciphertext, so that destroying a key
// (crypto-shredding) reaches every copy of a value, including immutable
// backups, without mutating any record. This package defines the contract
// the data layer depends on and an in-memory Fake; the Postgres
// implementation and the LRU cache are decorators over the same interface.
//
// The store knows nothing about subjects, parties, or any domain concept.
// It holds wrapped DEKs keyed by the field value they protect, and shreds
// them for a set of record ids. The caller maps its own notion of "who" to
// a record set.
package keystore

import (
	"context"
	"errors"
)

// ErrIncompleteKey is returned when a Key is missing any of its identity
// components. A wrapped DEK with no tenant, record, or field has no
// addressable home and could never be fetched or shredded precisely.
var ErrIncompleteKey = errors.New("keystore: key needs tenant, record, and field")

// Key identifies one wrapped DEK by the field value it protects, scoped to a
// tenant. It mirrors the identity of a kura.record_field_values row —
// (tenant_id, record_id, field_name) — so there is exactly one DEK per
// encrypted field value.
type Key struct {
	TenantID  string
	RecordID  string
	FieldName string
}

// complete reports whether every identity component is present.
func (k Key) complete() bool {
	return k.TenantID != "" && k.RecordID != "" && k.FieldName != ""
}

// KeyStore persists wrapped data-encryption keys and shreds them by record.
//
// Implementations must be tenant-scoping: a Fetch or Shred for one tenant
// never reaches another tenant's keys, even when record and field ids
// coincide. Fetch reports an absent key as a clean miss (found == false, nil
// error), because a missing key is the expected, non-error state after a
// crypto-shred.
type KeyStore interface {
	// Store persists the wrapped DEK for the field value named by key.
	Store(ctx context.Context, key Key, wrappedDEK []byte) error

	// Fetch returns the wrapped DEK for key. A key that is absent — never
	// stored, or shredded — is a clean miss: (nil, false, nil).
	Fetch(ctx context.Context, key Key) (wrappedDEK []byte, found bool, err error)

	// Shred deletes every wrapped DEK for the given record ids within
	// tenantID and returns how many were deleted. This is crypto-shredding:
	// the values' ciphertext becomes permanently undecryptable. It is
	// expressed over record ids — a domain-agnostic set — never over any
	// subject concept.
	Shred(ctx context.Context, tenantID string, recordIDs []string) (deleted int, err error)
}
