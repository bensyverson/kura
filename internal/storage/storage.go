package storage

import (
	"context"
	"errors"
)

// Role names the access level a credential domain holds over a bucket.
// It is part of the storage model precisely because DO Spaces has no
// Object Lock / WORM: the achievable immutability posture is versioning
// plus a deny-delete bucket policy, administered from a credential domain
// separate from the runtime writer. Modelling the role explicitly means
// the test fake and the real Spaces implementation agree on who can
// destroy data and who merely appends it.
type Role int

const (
	// AppendOnly may write new objects but cannot overwrite or delete
	// existing ones. It is the runtime writer's posture — the API
	// appending to the audit-log bucket, the backup job appending to the
	// backups bucket.
	AppendOnly Role = iota
	// ReadWrite may read, write, overwrite, and delete. It is held only
	// by the separate administrative credential domain that owns the
	// bucket's lifecycle — never by the runtime writer.
	ReadWrite
)

// Errors returned by a Store.
var (
	// ErrNotFound is returned by Get or Delete for an absent key.
	ErrNotFound = errors.New("storage: object not found")
	// ErrOverwriteDenied is returned when an AppendOnly Store is asked to
	// Put a key that already exists. It mirrors the deny-delete bucket
	// policy denying version-overwrite from the runtime credential.
	ErrOverwriteDenied = errors.New("storage: overwrite denied for append-only role")
	// ErrDeleteDenied is returned when an AppendOnly Store is asked to
	// Delete. It mirrors the deny-delete bucket policy denying object and
	// version deletion from the runtime credential.
	ErrDeleteDenied = errors.New("storage: delete denied for append-only role")
)

// Store is an object-storage bucket as Kura uses it: private always,
// encrypted always, with a fixed credential domain and a declared
// retention policy. The interface is deliberately small — Kura writes
// whole objects (encrypted backup dumps, audit-log segments) and never
// mutates them in place.
//
// A Store carries a Role. Under AppendOnly, Put of an existing key and
// any Delete are refused; under ReadWrite they are permitted. The same
// concrete type serves both roles, so a caller wires an append-only
// runtime store and a read-write administrative store identically.
type Store interface {
	// Spec returns the immutable description of the bucket.
	Spec() BucketSpec
	// Role returns the access level this Store was opened with.
	Role() Role
	// Put writes data at key. Under AppendOnly, putting an existing key
	// returns ErrOverwriteDenied and leaves the stored object untouched.
	Put(ctx context.Context, key string, data []byte) error
	// Get returns the object at key, or ErrNotFound.
	Get(ctx context.Context, key string) ([]byte, error)
	// List returns the keys with the given prefix, in lexical order.
	List(ctx context.Context, prefix string) ([]string, error)
	// Delete removes the object at key. Under AppendOnly it returns
	// ErrDeleteDenied and leaves the object in place; under ReadWrite an
	// absent key returns ErrNotFound.
	Delete(ctx context.Context, key string) error
}
