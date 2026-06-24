// Package manifest is the keystone: the in-memory model, parser, and
// validator for a per-client schema manifest. One manifest file declares
// the client's entities, the relationships between them, and which
// fields carry which PII categories — and that one file drives the data
// browser, the CLI query/show verbs, the MCP data tools, and the Cedar
// policy IR. Resist building entity-specific logic into any of those
// surfaces; the manifest is the single input.
package manifest

import (
	"slices"

	"github.com/bensyverson/kura/internal/pii"
)

// Manifest is a parsed, validated per-client schema declaration.
type Manifest struct {
	Version  string   `json:"version"`
	Entities []Entity `json:"entities"`
}

// Entity is one kind of record the client stores.
type Entity struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`

	// AppendOnly, when true, makes records of this entity insert-only:
	// they may be created but never updated or deleted. Append-only
	// entities may still declare relationships and may be the target of
	// other entities' relationships (their records get referenced).
	AppendOnly bool `json:"append_only,omitempty"`

	Fields        []Field        `json:"fields"`
	Relationships []Relationship `json:"relationships,omitempty"`
}

// Field is one attribute of an Entity.
type Field struct {
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Type        FieldType `json:"type"`

	// PII, when non-nil, is the PII category this field carries. A nil
	// PII means the field is not personally identifying.
	PII *pii.Category `json:"pii,omitempty"`
}

// Relationship is a typed edge from one Entity to another.
type Relationship struct {
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Kind        RelationshipKind `json:"kind"`
	Target      string           `json:"target"`
}

// FieldType is the recognized data type of a Field.
type FieldType string

const (
	FieldString FieldType = "string"
	// FieldText is free-text: assumed to contain PII, PII-scanned at
	// ingestion, and encrypted at rest.
	FieldText      FieldType = "text"
	FieldInteger   FieldType = "integer"
	FieldBoolean   FieldType = "boolean"
	FieldTimestamp FieldType = "timestamp"
)

var fieldTypes = []FieldType{
	FieldString, FieldText, FieldInteger, FieldBoolean, FieldTimestamp,
}

// Valid reports whether t is a recognized field type.
func (t FieldType) Valid() bool {
	return slices.Contains(fieldTypes, t)
}

// RelationshipKind is the cardinality of a Relationship's target.
type RelationshipKind string

const (
	RelationshipOne  RelationshipKind = "one"
	RelationshipMany RelationshipKind = "many"
)

// Valid reports whether k is a recognized relationship kind.
func (k RelationshipKind) Valid() bool {
	return k == RelationshipOne || k == RelationshipMany
}

// Entity returns the entity with the given name. The bool is false if no
// such entity exists.
func (m *Manifest) Entity(name string) (*Entity, bool) {
	for i := range m.Entities {
		if m.Entities[i].Name == name {
			return &m.Entities[i], true
		}
	}
	return nil, false
}

// Field returns the field with the given name. The bool is false if no
// such field exists on the entity.
func (e *Entity) Field(name string) (*Field, bool) {
	for i := range e.Fields {
		if e.Fields[i].Name == name {
			return &e.Fields[i], true
		}
	}
	return nil, false
}
