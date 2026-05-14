package data

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

const testEncKey = "test-record-encryption-key"

// NewPostgresStore must reject a misconfiguration rather than build a
// store that cannot read safely — a nil pool, an empty tenant id (RLS
// would then hide everything), or an empty encryption key (decryption
// would silently fail).
func TestNewPostgresStoreRejectsMisconfiguration(t *testing.T) {
	if _, err := NewPostgresStore(nil, "tenant", testEncKey); !errors.Is(err, ErrMissingDependency) {
		t.Errorf("nil db: err = %v, want ErrMissingDependency", err)
	}
}

// ruc: a record round-trips — rows written to the EAV tables assemble
// back into exactly the field map the gate's Fetcher expects.
func TestPostgresStoreGetRoundTrips(t *testing.T) {
	env := newDataTestEnv(t)
	tenant := newTenantID(t, env)
	id := seedRecord(t, env, tenant, "patient",
		map[string]string{"full_name": "Jane Doe", "mrn": "MRN-001"}, nil, testEncKey)

	store, err := NewPostgresStore(connectAsAPIRole(t, env), tenant, testEncKey)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
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
	tenant := newTenantID(t, env)
	id := seedRecord(t, env, tenant, "patient",
		map[string]string{"full_name": "Jane Doe"},
		map[string]string{"ssn": "123-45-6789"}, testEncKey)

	// At rest, the value is genuinely ciphertext.
	raw := rawEncryptedValue(t, env, id, "ssn")
	if len(raw) == 0 {
		t.Fatal("ssn stored with an empty value_encrypted")
	}
	if bytes.Contains(raw, []byte("123-45-6789")) {
		t.Fatal("ssn ciphertext at rest contains the plaintext")
	}

	store, err := NewPostgresStore(connectAsAPIRole(t, env), tenant, testEncKey)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
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
}

// frQ: reads set the tenant GUC, so RLS binds. A store scoped to one
// tenant cannot see another tenant's records — Get is a not-found and
// List is empty — while a store scoped to the owning tenant sees them,
// proving it is RLS doing the hiding and not a broken query.
func TestPostgresStoreCrossTenantReadIsDenied(t *testing.T) {
	env := newDataTestEnv(t)
	tenantA := newTenantID(t, env)
	tenantB := newTenantID(t, env)
	id := seedRecord(t, env, tenantA, "patient",
		map[string]string{"full_name": "Jane Doe"}, nil, testEncKey)

	apiPool := connectAsAPIRole(t, env)

	storeB, err := NewPostgresStore(apiPool, tenantB, testEncKey)
	if err != nil {
		t.Fatalf("NewPostgresStore(tenantB): %v", err)
	}
	if _, ok, err := storeB.Get(context.Background(), "patient", id); err != nil || ok {
		t.Errorf("cross-tenant Get = ok %v, err %v; want ok false, err nil (RLS hides it)", ok, err)
	}
	recs, err := storeB.List(context.Background(), "patient", 50, 0)
	if err != nil || len(recs) != 0 {
		t.Errorf("cross-tenant List = %+v, err %v; want empty, nil", recs, err)
	}

	storeA, err := NewPostgresStore(apiPool, tenantA, testEncKey)
	if err != nil {
		t.Fatalf("NewPostgresStore(tenantA): %v", err)
	}
	if _, ok, err := storeA.Get(context.Background(), "patient", id); err != nil || !ok {
		t.Errorf("same-tenant Get = ok %v, err %v; want ok true (the record is there for its owner)", ok, err)
	}
}

// fvP: list reads are bounded and stably ordered, so pagination over
// them is well-defined.
func TestPostgresStoreListIsOrderedAndPaginated(t *testing.T) {
	env := newDataTestEnv(t)
	tenant := newTenantID(t, env)
	var ids []string
	for _, name := range []string{"Alice", "Bob", "Carol", "Dave", "Erin"} {
		ids = append(ids, seedRecord(t, env, tenant, "patient",
			map[string]string{"full_name": name}, nil, testEncKey))
	}

	store, err := NewPostgresStore(connectAsAPIRole(t, env), tenant, testEncKey)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
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
	tenant := newTenantID(t, env)
	seedRecord(t, env, tenant, "patient", map[string]string{"full_name": "Jane Doe"}, nil, testEncKey)

	store, err := NewPostgresStore(connectAsAPIRole(t, env), tenant, testEncKey)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
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
	tenant := newTenantID(t, env)
	id := seedRecord(t, env, tenant, "doctor", map[string]string{"full_name": "Dr. Who"}, nil, testEncKey)

	store, err := NewPostgresStore(connectAsAPIRole(t, env), tenant, testEncKey)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	if _, ok, err := store.Get(context.Background(), "patient", id); err != nil || ok {
		t.Errorf("Get(doctor id under patient) = ok %v, err %v; want ok false", ok, err)
	}
}

// PostgresStore satisfies the RecordStore interface.
func TestPostgresStoreIsARecordStore(t *testing.T) {
	var _ RecordStore = (*PostgresStore)(nil)
}
