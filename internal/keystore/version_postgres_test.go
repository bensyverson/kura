package keystore_test

import (
	"context"
	"testing"

	"github.com/bensyverson/kura/internal/keystore"
)

// Against the real key store, Store writes the supplied kek_version into the
// row rather than the column default — so a post-rotation write under the
// active (v2) KEK is labelled v2 in the table, and the next rotation selects
// it correctly.
func TestPostgresStorePersistsSuppliedVersion(t *testing.T) {
	ctx := context.Background()
	pool := newKeystorePool(t)
	ks, err := keystore.NewPostgresStore(pool)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	k := keystore.Key{TenantID: newUUID(t), RecordID: newUUID(t), FieldName: "email"}

	if err := ks.Store(ctx, k, []byte("wrapped-under-v3"), 3); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if v := kekVersion(t, pool, k); v != 3 {
		t.Errorf("stored kek_version = %d, want 3", v)
	}
}
