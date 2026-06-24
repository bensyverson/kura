package keystore_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/bensyverson/kura/internal/db"
	"github.com/bensyverson/kura/internal/keystore"
)

// newKeystorePool provisions a fresh key-store database on the integration
// test cluster and brings it to the key-store schema. Physical separation
// from the main database is a production property (ADR 0002); on the test
// cluster a second fresh database is the correct analogue. It skips when no
// test cluster is configured so `go test ./...` stays green without one.
func newKeystorePool(t *testing.T) *sql.DB {
	t.Helper()
	base := os.Getenv("KURA_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("KURA_TEST_DATABASE_URL not set; skipping integration test")
	}
	admin, err := db.Open(base)
	if err != nil {
		t.Fatalf("connecting to test cluster: %v", err)
	}
	name := fmt.Sprintf("kura_keystore_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE DATABASE "` + name + `"`); err != nil {
		admin.Close()
		t.Fatalf("creating key-store test database: %v", err)
	}
	u, err := url.Parse(base)
	if err != nil {
		admin.Close()
		t.Fatalf("parsing test DSN: %v", err)
	}
	u.Path = "/" + name
	pool, err := db.Open(u.String())
	if err != nil {
		admin.Close()
		t.Fatalf("connecting to key-store test database: %v", err)
	}
	if err := db.MigrateKeystore(context.Background(), pool); err != nil {
		pool.Close()
		admin.Close()
		t.Fatalf("migrating key store: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := admin.Exec(`DROP DATABASE IF EXISTS "` + name + `" WITH (FORCE)`); err != nil {
			t.Logf("dropping key-store test database: %v", err)
		}
		admin.Close()
	})
	return pool
}

// newUUID returns a random canonical (lowercase, hyphenated) UUID string,
// matching how record_id and tenant_id appear in the main database.
func newUUID(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func TestPostgresStoreFetchRoundTrip(t *testing.T) {
	ctx := context.Background()
	ks, err := keystore.NewPostgresStore(newKeystorePool(t))
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	tenant, record := newUUID(t), newUUID(t)
	k := keystore.Key{TenantID: tenant, RecordID: record, FieldName: "email"}
	wrapped := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	if err := ks.Store(ctx, k, wrapped); err != nil {
		t.Fatalf("Store: %v", err)
	}
	got, found, err := ks.Fetch(ctx, k)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !found || string(got) != string(wrapped) {
		t.Fatalf("Fetch = %x found=%v, want %x/true", got, found, wrapped)
	}
}

func TestPostgresFetchMissIsClean(t *testing.T) {
	ctx := context.Background()
	ks, _ := keystore.NewPostgresStore(newKeystorePool(t))
	_, found, err := ks.Fetch(ctx, keystore.Key{TenantID: newUUID(t), RecordID: newUUID(t), FieldName: "email"})
	if err != nil {
		t.Fatalf("Fetch of absent key returned error %v, want clean miss", err)
	}
	if found {
		t.Fatal("Fetch found = true for absent key")
	}
}

func TestPostgresFetchAfterShredIsClean(t *testing.T) {
	ctx := context.Background()
	ks, _ := keystore.NewPostgresStore(newKeystorePool(t))
	tenant, record := newUUID(t), newUUID(t)
	k := keystore.Key{TenantID: tenant, RecordID: record, FieldName: "email"}
	if err := ks.Store(ctx, k, []byte("dek")); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if _, err := ks.Shred(ctx, tenant, []string{record}); err != nil {
		t.Fatalf("Shred: %v", err)
	}
	_, found, err := ks.Fetch(ctx, k)
	if err != nil {
		t.Fatalf("Fetch after shred returned error %v, want clean miss", err)
	}
	if found {
		t.Fatal("DEK still fetchable after shred")
	}
}

func TestPostgresShredDeletesTargetedRecordsOnly(t *testing.T) {
	ctx := context.Background()
	ks, _ := keystore.NewPostgresStore(newKeystorePool(t))
	tenant := newUUID(t)
	r1, r2 := newUUID(t), newUUID(t)
	store := func(record, field string) {
		if err := ks.Store(ctx, keystore.Key{TenantID: tenant, RecordID: record, FieldName: field}, []byte("d")); err != nil {
			t.Fatalf("Store: %v", err)
		}
	}
	store(r1, "email")
	store(r1, "phone")
	store(r2, "email")

	deleted, err := ks.Shred(ctx, tenant, []string{r1})
	if err != nil {
		t.Fatalf("Shred: %v", err)
	}
	if deleted != 2 {
		t.Fatalf("Shred deleted = %d, want 2", deleted)
	}
	if _, found, _ := ks.Fetch(ctx, keystore.Key{TenantID: tenant, RecordID: r2, FieldName: "email"}); !found {
		t.Error("r2 was deleted by a shred targeting only r1")
	}
}

func TestPostgresTenantIsolation(t *testing.T) {
	ctx := context.Background()
	ks, _ := keystore.NewPostgresStore(newKeystorePool(t))
	tenantA, tenantB := newUUID(t), newUUID(t)
	record := newUUID(t) // same record id under both tenants
	must(t, ks.Store(ctx, keystore.Key{TenantID: tenantA, RecordID: record, FieldName: "email"}, []byte("A")))
	must(t, ks.Store(ctx, keystore.Key{TenantID: tenantB, RecordID: record, FieldName: "email"}, []byte("B")))

	// Fetch is scoped to its key's tenant.
	got, found, _ := ks.Fetch(ctx, keystore.Key{TenantID: tenantA, RecordID: record, FieldName: "email"})
	if !found || string(got) != "A" {
		t.Fatalf("tenantA Fetch = %q found=%v, want A/true", got, found)
	}
	// Shredding tenantA's record must not reach tenantB's identically-keyed row.
	if _, err := ks.Shred(ctx, tenantA, []string{record}); err != nil {
		t.Fatalf("Shred: %v", err)
	}
	if _, found, _ := ks.Fetch(ctx, keystore.Key{TenantID: tenantB, RecordID: record, FieldName: "email"}); !found {
		t.Error("tenantB's DEK was deleted by a shred scoped to tenantA")
	}
}
