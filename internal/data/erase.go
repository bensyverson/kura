package data

import "context"

// Eraser crypto-shreds the encrypted field values of a set of records: it
// destroys their per-value DEKs, rendering the ciphertext permanently
// undecryptable in every copy — the live database, replicas, and the
// deny-delete immutable backup alike — without mutating any record.
//
// This is the erasure primitive Kura exposes (ADR 0002). It is expressed
// over record ids, a domain-agnostic set; the caller maps its own notion of
// "who" to a record set. Because it never touches kura.records, it is
// compatible with append-only entities: the append-only trigger, which
// guards UPDATE and DELETE, is never engaged.
type Eraser interface {
	// Erase shreds the DEKs for the given records within the store's tenant
	// and returns how many wrapped DEKs were destroyed. Erasing a record with
	// no encrypted fields, or one already erased, is harmless and idempotent.
	Erase(ctx context.Context, recordIDs []string) (shredded int, err error)
}

// Erase satisfies the Eraser seam for the in-memory store. MemStore is a
// dev/test double that holds record fields in the clear, so it has no
// wrapped DEKs to crypto-shred — there is nothing to destroy. It is a
// no-op that reports zero keys shredded, present only so `kura serve` can
// boot against the in-memory store; real crypto-shredding is a
// PostgresStore capability.
func (m *MemStore) Erase(_ context.Context, _ []string) (int, error) {
	return 0, nil
}

// Erase crypto-shreds the DEKs for recordIDs through the key-store cache,
// which both deletes the wrapped DEKs from the key store and evicts any
// cached copies — so an erased value can never be decrypted from a stale
// cache entry. The record rows are left untouched; only the external keys
// are destroyed.
func (s *PostgresStore) Erase(ctx context.Context, recordIDs []string) (int, error) {
	return s.cache.Shred(ctx, s.tenantID, recordIDs)
}
