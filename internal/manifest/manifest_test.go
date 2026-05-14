package manifest

import (
	"strings"
	"testing"

	"github.com/bensyverson/kura/internal/pii"
)

func TestParseValidManifest(t *testing.T) {
	m, err := ParseFile("testdata/valid.json")
	if err != nil {
		t.Fatalf("valid manifest failed to parse: %v", err)
	}
	if m.Version != "1" {
		t.Errorf("version = %q, want \"1\"", m.Version)
	}
	if len(m.Entities) != 2 {
		t.Fatalf("expected 2 entities, got %d", len(m.Entities))
	}

	cust, ok := m.Entity("customer")
	if !ok {
		t.Fatal(`Entity("customer") not found`)
	}

	email, ok := cust.Field("email")
	if !ok {
		t.Fatal(`customer has no "email" field`)
	}
	if email.PII == nil || *email.PII != pii.CategoryEmail {
		t.Errorf("customer.email did not carry the private_email category: %+v", email)
	}

	id, ok := cust.Field("id")
	if !ok {
		t.Fatal(`customer has no "id" field`)
	}
	if id.PII != nil {
		t.Errorf("customer.id should not be tagged PII, got %v", *id.PII)
	}
}

// "relationships resolve" — a relationship's target names a real entity in
// the same manifest.
func TestRelationshipsResolve(t *testing.T) {
	m, err := ParseFile("testdata/valid.json")
	if err != nil {
		t.Fatalf("valid manifest failed to parse: %v", err)
	}
	cust, _ := m.Entity("customer")
	if len(cust.Relationships) != 1 {
		t.Fatalf("expected 1 relationship on customer, got %d", len(cust.Relationships))
	}
	rel := cust.Relationships[0]
	if rel.Kind != RelationshipMany {
		t.Errorf("customer.orders kind = %q, want %q", rel.Kind, RelationshipMany)
	}
	target, ok := m.Entity(rel.Target)
	if !ok || target.Name != "order" {
		t.Errorf("customer.orders did not resolve to the order entity")
	}
}

func TestParseRejectsMalformedJSON(t *testing.T) {
	_, err := Parse([]byte(`{ "version": "1", "entities": `))
	if err == nil {
		t.Fatal("expected an error parsing malformed JSON")
	}
	if !strings.Contains(err.Error(), "manifest") {
		t.Errorf("error should identify the manifest: %v", err)
	}
}

// Every malformed-manifest case must fail validation with a specific,
// matchable error.
func TestValidationRejectsMalformedManifests(t *testing.T) {
	cases := []struct {
		name string
		json string
		want string
	}{
		{
			"no entities",
			`{"version":"1","entities":[]}`,
			"at least one entity",
		},
		{
			"missing version",
			`{"entities":[{"name":"x","fields":[{"name":"id","type":"string"}]}]}`,
			"version",
		},
		{
			"entity with empty name",
			`{"version":"1","entities":[{"name":"","fields":[{"name":"id","type":"string"}]}]}`,
			"entity name",
		},
		{
			"duplicate entity names",
			`{"version":"1","entities":[
				{"name":"dup","fields":[{"name":"id","type":"string"}]},
				{"name":"dup","fields":[{"name":"id","type":"string"}]}]}`,
			"duplicate entity",
		},
		{
			"entity with no fields",
			`{"version":"1","entities":[{"name":"x","fields":[]}]}`,
			"at least one field",
		},
		{
			"field with empty name",
			`{"version":"1","entities":[{"name":"x","fields":[{"name":"","type":"string"}]}]}`,
			"field name",
		},
		{
			"duplicate field names",
			`{"version":"1","entities":[{"name":"x","fields":[
				{"name":"id","type":"string"},{"name":"id","type":"string"}]}]}`,
			"duplicate field",
		},
		{
			"unrecognized field type",
			`{"version":"1","entities":[{"name":"x","fields":[{"name":"id","type":"blob"}]}]}`,
			"field type",
		},
		{
			"unrecognized PII category",
			`{"version":"1","entities":[{"name":"x","fields":[
				{"name":"id","type":"string","pii":"social_security"}]}]}`,
			"PII category",
		},
		{
			"relationship with empty name",
			`{"version":"1","entities":[{"name":"x","fields":[{"name":"id","type":"string"}],
				"relationships":[{"name":"","kind":"one","target":"x"}]}]}`,
			"relationship name",
		},
		{
			"relationship with empty target",
			`{"version":"1","entities":[{"name":"x","fields":[{"name":"id","type":"string"}],
				"relationships":[{"name":"r","kind":"one","target":""}]}]}`,
			"target",
		},
		{
			"dangling relationship target",
			`{"version":"1","entities":[{"name":"x","fields":[{"name":"id","type":"string"}],
				"relationships":[{"name":"r","kind":"one","target":"ghost"}]}]}`,
			`"ghost"`,
		},
		{
			"invalid relationship kind",
			`{"version":"1","entities":[{"name":"x","fields":[{"name":"id","type":"string"}],
				"relationships":[{"name":"r","kind":"sometimes","target":"x"}]}]}`,
			"relationship kind",
		},
		{
			"duplicate relationship names",
			`{"version":"1","entities":[{"name":"x","fields":[{"name":"id","type":"string"}],
				"relationships":[
					{"name":"r","kind":"one","target":"x"},
					{"name":"r","kind":"one","target":"x"}]}]}`,
			"duplicate relationship",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.json))
			if err == nil {
				t.Fatalf("expected validation to reject %q", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}
