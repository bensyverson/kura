package manifest

import (
	"encoding/json"
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

// "append-only round-trips" — an entity can declare append_only, the flag
// survives a parse → marshal → parse round-trip, and an append-only entity
// may both declare its own relationships and be the target of another
// entity's relationship (append-only events get referenced).
func TestAppendOnlyRoundTrips(t *testing.T) {
	m, err := ParseFile("testdata/valid.json")
	if err != nil {
		t.Fatalf("valid manifest failed to parse: %v", err)
	}

	order, ok := m.Entity("order")
	if !ok {
		t.Fatal(`Entity("order") not found`)
	}
	if !order.AppendOnly {
		t.Errorf("order should be append_only")
	}

	cust, ok := m.Entity("customer")
	if !ok {
		t.Fatal(`Entity("customer") not found`)
	}
	if cust.AppendOnly {
		t.Errorf("customer should not be append_only (omitempty default)")
	}

	// An append-only entity may declare its own relationships...
	if len(order.Relationships) != 1 {
		t.Errorf("append-only order should still declare its relationship, got %d", len(order.Relationships))
	}
	// ...and be the target of another entity's relationship.
	if cust.Relationships[0].Target != "order" {
		t.Errorf("append-only order should be a valid relationship target")
	}

	// The flag survives a JSON round-trip.
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	m2, err := Parse(data)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	order2, _ := m2.Entity("order")
	if !order2.AppendOnly {
		t.Errorf("append_only did not survive the round-trip")
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
