package keystore_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/bensyverson/kura/internal/crypto"
	"github.com/bensyverson/kura/internal/keystore"
)

// kekVersion reads the stored kek_version for one wrapped DEK directly from
// the table, tenant-scoped so the RLS policy is satisfied. Rotation's whole
// resumability contract rests on this column, so the integration test asserts
// it at the source rather than inferring it.
func kekVersion(t *testing.T, pool *sql.DB, k keystore.Key) int {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('kura.tenant_id', $1, true)`, k.TenantID); err != nil {
		t.Fatalf("set tenant: %v", err)
	}
	var v int
	if err := tx.QueryRowContext(ctx,
		`SELECT kek_version FROM kura.wrapped_deks
		 WHERE tenant_id::text = $1 AND record_id::text = $2 AND field_name = $3`,
		k.TenantID, k.RecordID, k.FieldName).Scan(&v); err != nil {
		t.Fatalf("reading kek_version: %v", err)
	}
	return v
}

// storeSealed wraps a fresh DEK under w, stores it, and returns the key and a
// ciphertext sealed under that DEK — the persisted analogue of the unit
// test's seedValues, against the real key-store instance.
func storeSealed(t *testing.T, ctx context.Context, ks keystore.KeyStore, tenant string, w crypto.Wrapper, plain string) (keystore.Key, []byte) {
	t.Helper()
	dek, err := crypto.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	sealed, err := crypto.Encrypt(dek, []byte(plain))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	wrapped, err := w.Wrap(dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	key := keystore.Key{TenantID: tenant, RecordID: newUUID(t), FieldName: "email"}
	if err := ks.Store(ctx, key, wrapped, 1); err != nil {
		t.Fatalf("Store: %v", err)
	}
	return key, sealed
}

// Against the real key-store instance: rotation re-wraps every DEK, bumps
// kek_version, and leaves the value decryptable under the new KEK — while the
// stored ciphertext (which rotation never touches) is unchanged.
func TestPostgresRotateReWrapsInPlace(t *testing.T) {
	ctx := context.Background()
	pool := newKeystorePool(t)
	ks, err := keystore.NewPostgresStore(pool)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	oldW := wrapperOf(t, 0x11)
	newW := wrapperOf(t, 0x22)
	tenant := newUUID(t)

	k1, sealed1 := storeSealed(t, ctx, ks, tenant, oldW, "alice@example.com")
	k2, sealed2 := storeSealed(t, ctx, ks, tenant, oldW, "bob@example.com")

	if kekVersion(t, pool, k1) != 1 {
		t.Fatalf("pre-rotation kek_version = %d, want 1", kekVersion(t, pool, k1))
	}

	rotated, err := keystore.Rotate(ctx, ks, tenant, 1, 2, 10, rewrapVia(oldW, newW), nil)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if rotated != 2 {
		t.Errorf("rotated %d, want 2", rotated)
	}

	for _, c := range []struct {
		key    keystore.Key
		sealed []byte
		plain  string
	}{{k1, sealed1, "alice@example.com"}, {k2, sealed2, "bob@example.com"}} {
		if v := kekVersion(t, pool, c.key); v != 2 {
			t.Errorf("%v: kek_version = %d, want 2", c.key, v)
		}
		wrapped, _, found, err := ks.Fetch(ctx, c.key)
		if err != nil || !found {
			t.Fatalf("Fetch(%v): found=%v err=%v", c.key, found, err)
		}
		dek, err := newW.Unwrap(wrapped)
		if err != nil {
			t.Fatalf("%v: unwrap under new KEK: %v", c.key, err)
		}
		if got, err := crypto.Decrypt(dek, c.sealed); err != nil || string(got) != c.plain {
			t.Errorf("%v: decrypt = %q err=%v, want %q", c.key, got, err, c.plain)
		}
	}
}

// Against the real instance, rotation is resumable: draining one row at a
// time and then re-invoking the driver completes every row exactly once, with
// none left at the old version.
func TestPostgresRotateIsResumable(t *testing.T) {
	ctx := context.Background()
	pool := newKeystorePool(t)
	ks, err := keystore.NewPostgresStore(pool)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	oldW := wrapperOf(t, 0x11)
	newW := wrapperOf(t, 0x22)
	tenant := newUUID(t)
	rw := rewrapVia(oldW, newW)

	var keys []keystore.Key
	for range 4 {
		k, _ := storeSealed(t, ctx, ks, tenant, oldW, "v")
		keys = append(keys, k)
	}

	// An interrupted run: one batch of a single row.
	first, err := ks.RotateBatch(ctx, tenant, 1, 2, 1, rw)
	if err != nil {
		t.Fatalf("RotateBatch: %v", err)
	}
	if first != 1 {
		t.Fatalf("first batch rotated %d, want 1", first)
	}

	// Resume: the driver finishes the remaining three.
	rest, err := keystore.Rotate(ctx, ks, tenant, 1, 2, 2, rw, nil)
	if err != nil {
		t.Fatalf("resumed Rotate: %v", err)
	}
	if rest != 3 {
		t.Errorf("resumed rotation did %d, want 3", rest)
	}

	for _, k := range keys {
		if v := kekVersion(t, pool, k); v != 2 {
			t.Errorf("%v: kek_version = %d, want 2", k, v)
		}
	}
	left, err := ks.RotateBatch(ctx, tenant, 1, 2, 100, rw)
	if err != nil {
		t.Fatalf("drain check: %v", err)
	}
	if left != 0 {
		t.Errorf("%d rows still at v1 after completion", left)
	}
}
