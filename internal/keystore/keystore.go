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

// ErrInvalidRotation is returned when a rotation does not advance the KEK
// version — a toVersion at or below fromVersion. Rotation must move rows
// forward; a non-advancing rotation is a misconfiguration, never a silent
// no-op that could leave the operator believing keys were re-wrapped.
var ErrInvalidRotation = errors.New("keystore: rotation must advance the kek version")

// Rewrap re-seals a wrapped DEK: it unwraps under the retiring KEK and
// re-wraps under the incoming one, returning new wrapped bytes for the same
// DEK. Rotation calls it per row. The keystore holds no KEK material — the
// caller composes Rewrap from its wrap/unwrap capabilities — so the master
// key's blast radius on rotation is as small as it is on the write path.
type Rewrap func(oldWrapped []byte) (newWrapped []byte, err error)

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
	// Store persists the wrapped DEK for the field value named by key,
	// stamping it with version — the KEK generation that wrapped it. The
	// caller passes the version the wrapping key reported (KeyRing.WrapActive)
	// so the stored kek_version always matches the key that can open the DEK;
	// there is no implicit default that could mislabel a row during a rotation.
	Store(ctx context.Context, key Key, wrappedDEK []byte, version int) error

	// Fetch returns the wrapped DEK for key and the KEK generation
	// (kek_version) that wrapped it, so the read path can open the row under
	// the matching key. A key that is absent — never stored, or shredded — is
	// a clean miss: (nil, 0, false, nil).
	Fetch(ctx context.Context, key Key) (wrappedDEK []byte, version int, found bool, err error)

	// Shred deletes every wrapped DEK for the given record ids within
	// tenantID and returns how many were deleted. This is crypto-shredding:
	// the values' ciphertext becomes permanently undecryptable. It is
	// expressed over record ids — a domain-agnostic set — never over any
	// subject concept.
	Shred(ctx context.Context, tenantID string, recordIDs []string) (deleted int, err error)

	// RotateBatch re-wraps up to limit wrapped DEKs currently at fromVersion
	// within tenantID, advancing each to toVersion. For every selected row it
	// calls rewrap on the stored wrapped DEK and persists the result with
	// kek_version = toVersion, atomically, so a row is either fully advanced
	// or untouched. It returns how many rows were rotated; zero means no rows
	// remain at fromVersion. Rotation touches only the wrapping, never the
	// DEK, so ciphertext stays decryptable and byte-for-byte unchanged.
	//
	// Selecting strictly on fromVersion makes rotation resumable and
	// idempotent: a re-run after an interruption re-selects only the
	// not-yet-advanced rows and never double-wraps one already at toVersion.
	// A toVersion at or below fromVersion is ErrInvalidRotation.
	RotateBatch(ctx context.Context, tenantID string, fromVersion, toVersion, limit int, rewrap Rewrap) (rotated int, err error)
}
