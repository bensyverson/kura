package data

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"slices"
	"testing"

	"github.com/bensyverson/kura/internal/crypto"
	"github.com/bensyverson/kura/internal/keystore"
)

// NewPostgresStore must reject a misconfiguration rather than build a store
// that cannot read or write safely — a nil pool, an empty tenant id (RLS
// would then hide everything), or a missing crypto collaborator (the key
// store, the KEK wrap capability, or the read cache), without which
// encrypted fields could be neither sealed nor opened.
func TestNewPostgresStoreRejectsMisconfiguration(t *testing.T) {
	ce := newCryptoEnv(t)
	// A placeholder pool: construction only inspects non-nil-ness, never
	// dials, so the zero value is enough to isolate the other checks.
	pool := &sql.DB{}
	cases := []struct {
		name    string
		db      *sql.DB
		tenant  string
		keys    keystore.KeyStore
		keyring *crypto.KeyRing
		cache   *keystore.Cache
	}{
		{"nil db", nil, "tenant", ce.Keys, ce.Ring, ce.Cache},
		{"empty tenant", pool, "", ce.Keys, ce.Ring, ce.Cache},
		{"nil keys", pool, "tenant", nil, ce.Ring, ce.Cache},
		{"nil keyring", pool, "tenant", ce.Keys, nil, ce.Cache},
		{"nil cache", pool, "tenant", ce.Keys, ce.Ring, nil},
	}
	for _, c := range cases {
		if _, err := NewPostgresStore(c.db, c.tenant, c.keys, c.keyring, c.cache); !errors.Is(err, ErrMissingDependency) {
			t.Errorf("%s: err = %v, want ErrMissingDependency", c.name, err)
		}
	}
}

// ruc: a record round-trips — rows written to the EAV tables assemble
// back into exactly the field map the gate's Fetcher expects.
func TestPostgresStoreGetRoundTrips(t *testing.T) {
	env := newDataTestEnv(t)
	ce := newCryptoEnv(t)
	tenant := newTenantID(t, env)
	id := seedRecord(t, env, tenant, "patient",
		map[string]string{"full_name": "Jane Doe", "mrn": "MRN-001"}, nil, ce)

	store := newRecordStore(t, connectAsAPIRole(t, env), tenant, ce)
	rec, ok, err := store.Get(context.Background(), "patient", id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("Get: record not found, want found")
	}
	if rec.ID != id {
		t.Errorf("rec.ID = %q, want %q", rec.ID, id)
	}
	if rec.Fields["full_name"] != "Jane Doe" || rec.Fields["mrn"] != "MRN-001" {
		t.Errorf("rec.Fields = %+v, want full_name/mrn round-tripped", rec.Fields)
	}
	if len(rec.Fields) != 2 {
		t.Errorf("rec.Fields has %d entries, want 2", len(rec.Fields))
	}
}

// 11s: a high-sensitivity or free-text value is stored encrypted and
// decrypted transparently on read — the store hands back plaintext, but
// the bytes at rest are ciphertext.
func TestPostgresStoreDecryptsEncryptedFields(t *testing.T) {
	env := newDataTestEnv(t)
	ce := newCryptoEnv(t)
	tenant := newTenantID(t, env)
	id := seedRecord(t, env, tenant, "patient",
		map[string]string{"full_name": "Jane Doe"},
		map[string]string{"ssn": "123-45-6789"}, ce)

	// At rest, the value is genuinely ciphertext.
	raw := rawEncryptedValue(t, env, id, "ssn")
	if len(raw) == 0 {
		t.Fatal("ssn stored with an empty value_encrypted")
	}
	if bytes.Contains(raw, []byte("123-45-6789")) {
		t.Fatal("ssn ciphertext at rest contains the plaintext")
	}

	store := newRecordStore(t, connectAsAPIRole(t, env), tenant, ce)
	rec, ok, err := store.Get(context.Background(), "patient", id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("Get: record not found")
	}
	if rec.Fields["ssn"] != "123-45-6789" {
		t.Errorf("ssn = %q, want the decrypted plaintext", rec.Fields["ssn"])
	}
	if rec.Fields["full_name"] != "Jane Doe" {
		t.Errorf("full_name = %q, want plaintext", rec.Fields["full_name"])
	}
	if len(rec.Erased) != 0 {
		t.Errorf("rec.Erased = %v, want none (nothing shredded)", rec.Erased)
	}
}

// A field whose DEK has been crypto-shredded reads back as erased: absent
// from Fields, named in Erased, and never surfaced as ciphertext or an
// error. This is the read half of crypto-shredding — the ciphertext row is
// untouched; only the key is gone.
func TestPostgresStoreShreddedFieldReadsAsErased(t *testing.T) {
	env := newDataTestEnv(t)
	ce := newCryptoEnv(t)
	tenant := newTenantID(t, env)
	id := seedRecord(t, env, tenant, "patient",
		map[string]string{"full_name": "Jane Doe"},
		map[string]string{"ssn": "123-45-6789"}, ce)

	store := newRecordStore(t, connectAsAPIRole(t, env), tenant, ce)

	// Shred the record's DEKs through the same cache the store reads
	// through, so no stale entry can still decrypt.
	if _, err := ce.Cache.Shred(context.Background(), tenant, []string{id}); err != nil {
		t.Fatalf("Shred: %v", err)
	}

	rec, ok, err := store.Get(context.Background(), "patient", id)
	if err != nil {
		t.Fatalf("Get after shred: %v", err)
	}
	if !ok {
		t.Fatal("Get after shred: record not found; erasure must not delete the record")
	}
	if _, present := rec.Fields["ssn"]; present {
		t.Errorf("ssn is still present in Fields (%q) after its DEK was shredded", rec.Fields["ssn"])
	}
	if !contains(rec.Erased, "ssn") {
		t.Errorf("rec.Erased = %v, want it to name ssn", rec.Erased)
	}
	// A non-PII plaintext field is untouched by erasure of another field.
	if rec.Fields["full_name"] != "Jane Doe" {
		t.Errorf("full_name = %q, want it intact after ssn was erased", rec.Fields["full_name"])
	}
}

// UZX: a genuine authentication failure — tampered ciphertext under an
// intact DEK — stays a hard error on read, distinct from the erased
// sentinel. The field is neither decrypted nor reported as erased. This is
// the guard that keeps crypto-shredding (key destroyed, value erased by
// design) from being confused with corruption (key present, value
// unreadable), so an attacker cannot pass tampering off as a routine
// erased read.
func TestPostgresStoreGenuineDecryptFailureIsHardError(t *testing.T) {
	env := newDataTestEnv(t)
	ce := newCryptoEnv(t)
	tenant := newTenantID(t, env)
	id := seedRecord(t, env, tenant, "patient",
		map[string]string{"full_name": "Jane Doe"},
		map[string]string{"ssn": "123-45-6789"}, ce)

	// Corrupt the ciphertext at rest while leaving the DEK intact, so the
	// read reaches decryption and GCM authentication fails — as it would for
	// tampering or a wrong KEK.
	raw := rawEncryptedValue(t, env, id, "ssn")
	tampered := bytes.Clone(raw)
	tampered[len(tampered)-1] ^= 0xFF
	if _, err := env.DB.Exec(
		`UPDATE kura.record_field_values SET value_encrypted = $1 WHERE record_id = $2 AND field_name = 'ssn'`,
		tampered, id); err != nil {
		t.Fatalf("corrupting ciphertext: %v", err)
	}

	store := newRecordStore(t, connectAsAPIRole(t, env), tenant, ce)
	rec, ok, err := store.Get(context.Background(), "patient", id)
	if err == nil {
		t.Fatalf("Get of tampered ciphertext: want a hard error, got ok=%v rec=%+v", ok, rec)
	}
	// The failure must never masquerade as erasure.
	if contains(rec.Erased, "ssn") {
		t.Errorf("tampered field reported as erased (%v); a genuine decrypt failure must stay an error", rec.Erased)
	}
}

// frQ: reads set the tenant GUC, so RLS binds. A store scoped to one
// tenant cannot see another tenant's records — Get is a not-found and
// List is empty — while a store scoped to the owning tenant sees them,
// proving it is RLS doing the hiding and not a broken query.
func TestPostgresStoreCrossTenantReadIsDenied(t *testing.T) {
	env := newDataTestEnv(t)
	ce := newCryptoEnv(t)
	tenantA := newTenantID(t, env)
	tenantB := newTenantID(t, env)
	id := seedRecord(t, env, tenantA, "patient",
		map[string]string{"full_name": "Jane Doe"}, nil, ce)

	apiPool := connectAsAPIRole(t, env)

	storeB := newRecordStore(t, apiPool, tenantB, ce)
	if _, ok, err := storeB.Get(context.Background(), "patient", id); err != nil || ok {
		t.Errorf("cross-tenant Get = ok %v, err %v; want ok false, err nil (RLS hides it)", ok, err)
	}
	recs, err := storeB.List(context.Background(), "patient", 50, 0)
	if err != nil || len(recs) != 0 {
		t.Errorf("cross-tenant List = %+v, err %v; want empty, nil", recs, err)
	}

	storeA := newRecordStore(t, apiPool, tenantA, ce)
	if _, ok, err := storeA.Get(context.Background(), "patient", id); err != nil || !ok {
		t.Errorf("same-tenant Get = ok %v, err %v; want ok true (the record is there for its owner)", ok, err)
	}
}

// fvP: list reads are bounded and stably ordered, so pagination over
// them is well-defined.
func TestPostgresStoreListIsOrderedAndPaginated(t *testing.T) {
	env := newDataTestEnv(t)
	ce := newCryptoEnv(t)
	tenant := newTenantID(t, env)
	var ids []string
	for _, name := range []string{"Alice", "Bob", "Carol", "Dave", "Erin"} {
		ids = append(ids, seedRecord(t, env, tenant, "patient",
			map[string]string{"full_name": name}, nil, ce))
	}

	store := newRecordStore(t, connectAsAPIRole(t, env), tenant, ce)
	ctx := context.Background()

	all, err := store.List(ctx, "patient", 50, 0)
	if err != nil {
		t.Fatalf("List(all): %v", err)
	}
	if len(all) != 5 {
		t.Fatalf("List(all) returned %d records, want 5", len(all))
	}
	for i, id := range ids {
		if all[i].ID != id {
			t.Errorf("List is not in insertion order: position %d = %q, want %q", i, all[i].ID, id)
		}
	}

	page, err := store.List(ctx, "patient", 2, 1)
	if err != nil {
		t.Fatalf("List(page): %v", err)
	}
	if len(page) != 2 || page[0].ID != ids[1] || page[1].ID != ids[2] {
		t.Errorf("List(limit 2, offset 1) returned the wrong page: %+v", page)
	}
	if page[0].Fields["full_name"] != "Bob" {
		t.Errorf("page[0] full_name = %q, want Bob", page[0].Fields["full_name"])
	}

	// An offset past the end is an empty page, not an error.
	tail, err := store.List(ctx, "patient", 10, 99)
	if err != nil || len(tail) != 0 {
		t.Errorf("List past the end = %+v, err %v; want empty, nil", tail, err)
	}
}

// A Get for an id that does not exist — or one that is not even a valid
// uuid — is a not-found, not an error: the caller maps it to a 404, not
// a 500.
func TestPostgresStoreGetMissingRecordIsNotFound(t *testing.T) {
	env := newDataTestEnv(t)
	ce := newCryptoEnv(t)
	tenant := newTenantID(t, env)
	seedRecord(t, env, tenant, "patient", map[string]string{"full_name": "Jane Doe"}, nil, ce)

	store := newRecordStore(t, connectAsAPIRole(t, env), tenant, ce)
	ctx := context.Background()

	if _, ok, err := store.Get(ctx, "patient", "11111111-1111-1111-1111-111111111111"); err != nil || ok {
		t.Errorf("Get(absent uuid) = ok %v, err %v; want ok false, err nil", ok, err)
	}
	if _, ok, err := store.Get(ctx, "patient", "not-a-uuid"); err != nil || ok {
		t.Errorf("Get(malformed id) = ok %v, err %v; want ok false, err nil", ok, err)
	}
}

// A record that exists but carries the wrong entity name is not returned
// under the requested entity.
func TestPostgresStoreGetRespectsEntity(t *testing.T) {
	env := newDataTestEnv(t)
	ce := newCryptoEnv(t)
	tenant := newTenantID(t, env)
	id := seedRecord(t, env, tenant, "doctor", map[string]string{"full_name": "Dr. Who"}, nil, ce)

	store := newRecordStore(t, connectAsAPIRole(t, env), tenant, ce)
	if _, ok, err := store.Get(context.Background(), "patient", id); err != nil || ok {
		t.Errorf("Get(doctor id under patient) = ok %v, err %v; want ok false", ok, err)
	}
}

// Count returns the number of an entity's records, scoped by RLS like
// every other read: a store sees only its own tenant's rows, and an
// entity with none counts zero rather than erroring.
func TestPostgresStoreCount(t *testing.T) {
	env := newDataTestEnv(t)
	ce := newCryptoEnv(t)
	tenantA := newTenantID(t, env)
	tenantB := newTenantID(t, env)
	seedRecord(t, env, tenantA, "patient", map[string]string{"full_name": "Jane Doe"}, nil, ce)
	seedRecord(t, env, tenantA, "patient", map[string]string{"full_name": "John Roe"}, nil, ce)
	seedRecord(t, env, tenantA, "doctor", map[string]string{"full_name": "Dr. Who"}, nil, ce)
	seedRecord(t, env, tenantB, "patient", map[string]string{"full_name": "Other Tenant"}, nil, ce)

	apiPool := connectAsAPIRole(t, env)
	storeA := newRecordStore(t, apiPool, tenantA, ce)
	ctx := context.Background()

	if n, err := storeA.Count(ctx, "patient"); err != nil || n != 2 {
		t.Errorf("Count(patient) = %d, err %v; want 2, nil (RLS scopes to tenantA)", n, err)
	}
	if n, err := storeA.Count(ctx, "doctor"); err != nil || n != 1 {
		t.Errorf("Count(doctor) = %d, err %v; want 1, nil", n, err)
	}
	if n, err := storeA.Count(ctx, "ghost"); err != nil || n != 0 {
		t.Errorf("Count(unknown entity) = %d, err %v; want 0, nil", n, err)
	}
}

// PostgresStore satisfies the RecordStore interface.
func TestPostgresStoreIsARecordStore(t *testing.T) {
	var _ RecordStore = (*PostgresStore)(nil)
}

// contains reports whether s contains v — a tiny helper for asserting a
// field name appears in a Record's Erased list.
func contains(s []string, v string) bool {
	return slices.Contains(s, v)
}
