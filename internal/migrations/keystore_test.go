package migrations

import (
	"strings"
	"testing"
)

// The key store has its own migration lineage, embedded separately from the
// main 0001–000N set and applied against a different Postgres instance. It
// is numbered from 1 independently.
func TestKeystoreReturnsContiguousLineage(t *testing.T) {
	ms, err := Keystore()
	if err != nil {
		t.Fatalf("Keystore() error: %v", err)
	}
	if len(ms) == 0 {
		t.Fatal("Keystore() returned no migrations")
	}
	for i, m := range ms {
		if m.Number != i+1 {
			t.Errorf("keystore migration at index %d: Number = %d, want %d", i, m.Number, i+1)
		}
		if m.Name == "" || m.SQL == "" {
			t.Errorf("keystore migration %d: empty name or SQL", m.Number)
		}
	}
	if ms[0].Name != "keystore_schema" {
		t.Errorf("first keystore migration name = %q, want %q", ms[0].Name, "keystore_schema")
	}
}

// The wrapped-DEK table mirrors a record_field_values row's identity and
// carries the wrapped key plus its KEK version, under forced RLS consistent
// with the main schema's tenant isolation.
func TestKeystoreSchemaShape(t *testing.T) {
	ms, err := Keystore()
	if err != nil {
		t.Fatalf("Keystore() error: %v", err)
	}
	sql := ms[0].SQL
	for _, want := range []string{
		"tenant_id", "record_id", "field_name", // identity
		"wrapped_dek", "kek_version", // payload
		"bytea",
		"FORCE ROW LEVEL SECURITY",         // tenant isolation, owner included
		"current_setting('kura.tenant_id'", // keyed on the same GUC as the main schema
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("keystore_schema SQL missing %q", want)
		}
	}
}

// The main lineage must not absorb the keystore migrations: All() stays the
// contiguous main set, with no keystore_schema entry.
func TestAllExcludesKeystoreLineage(t *testing.T) {
	ms, err := All()
	if err != nil {
		t.Fatalf("All() error: %v", err)
	}
	for _, m := range ms {
		if m.Name == "keystore_schema" {
			t.Fatalf("All() leaked keystore migration %q into the main lineage", m.Name)
		}
	}
}
