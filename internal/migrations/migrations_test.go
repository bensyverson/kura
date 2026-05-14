package migrations

import "testing"

func TestAllReturnsContiguousOrderedMigrations(t *testing.T) {
	ms, err := All()
	if err != nil {
		t.Fatalf("All() error: %v", err)
	}
	if len(ms) == 0 {
		t.Fatal("All() returned no migrations")
	}
	for i, m := range ms {
		want := i + 1
		if m.Number != want {
			t.Errorf("migration at index %d: Number = %d, want %d", i, m.Number, want)
		}
		if m.Name == "" {
			t.Errorf("migration %d: empty Name", m.Number)
		}
		if m.SQL == "" {
			t.Errorf("migration %d: empty SQL", m.Number)
		}
	}
}

func TestAllParsesKnownMigrations(t *testing.T) {
	ms, err := All()
	if err != nil {
		t.Fatalf("All() error: %v", err)
	}
	want := []string{"app_schema", "row_level_security", "component_roles"}
	if len(ms) < len(want) {
		t.Fatalf("All() returned %d migrations, want at least %d", len(ms), len(want))
	}
	for i, name := range want {
		if ms[i].Name != name {
			t.Errorf("migration %d: Name = %q, want %q", i+1, ms[i].Name, name)
		}
	}
}

func TestParseFilename(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantNum int
		wantNm  string
		wantErr bool
	}{
		{"well formed", "0001_app_schema.sql", 1, "app_schema", false},
		{"multi-word name", "0012_add_index.sql", 12, "add_index", false},
		{"no underscore", "0001.sql", 0, "", true},
		{"non-numeric prefix", "abcd_thing.sql", 0, "", true},
		{"zero number", "0000_genesis.sql", 0, "", true},
		{"empty name", "0001_.sql", 0, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			num, nm, err := parseFilename(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseFilename(%q) = (%d, %q, nil), want error", tt.in, num, nm)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseFilename(%q) unexpected error: %v", tt.in, err)
			}
			if num != tt.wantNum || nm != tt.wantNm {
				t.Errorf("parseFilename(%q) = (%d, %q), want (%d, %q)", tt.in, num, nm, tt.wantNum, tt.wantNm)
			}
		})
	}
}
