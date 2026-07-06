package data

import (
	"context"
	"testing"
)

// MemStore is the in-memory dev/test double for the record store. It holds
// record fields in the clear, so it has no wrapped DEKs to crypto-shred:
// Erase must satisfy the Eraser seam (so `kura serve` boots in-memory) and
// report zero keys destroyed rather than pretending to shred anything.
func TestMemStoreEraseIsANoOp(t *testing.T) {
	var _ Eraser = (*MemStore)(nil)

	m := NewMemStore()
	shredded, err := m.Erase(context.Background(), []string{"r1", "r2"})
	if err != nil {
		t.Fatalf("Erase: %v", err)
	}
	if shredded != 0 {
		t.Errorf("shredded = %d, want 0 (MemStore holds no DEKs)", shredded)
	}
}
