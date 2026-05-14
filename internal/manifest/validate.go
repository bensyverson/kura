package manifest

import (
	"errors"
	"fmt"
)

// Validate checks the manifest for structural soundness and reports the
// first problem it finds with a specific, matchable error: a missing
// version, an entity with no name or no fields, duplicate names,
// unrecognized field types or PII categories, and dangling relationship
// targets all fail loudly here rather than surfacing later as a confusing
// failure in a downstream surface.
func (m *Manifest) Validate() error {
	if m.Version == "" {
		return errors.New(`manifest: "version" is required`)
	}
	if len(m.Entities) == 0 {
		return errors.New("manifest: must declare at least one entity")
	}

	// First pass: every entity has a unique, non-empty name. Done before
	// the field/relationship pass so that relationship targets can be
	// resolved against the complete entity set.
	seenEntities := make(map[string]bool, len(m.Entities))
	for i := range m.Entities {
		name := m.Entities[i].Name
		if name == "" {
			return fmt.Errorf("manifest: entity name must not be empty (entity #%d)", i+1)
		}
		if seenEntities[name] {
			return fmt.Errorf("manifest: duplicate entity name %q", name)
		}
		seenEntities[name] = true
	}

	for i := range m.Entities {
		if err := m.validateEntity(&m.Entities[i]); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manifest) validateEntity(e *Entity) error {
	if len(e.Fields) == 0 {
		return fmt.Errorf("manifest: entity %q: must declare at least one field", e.Name)
	}

	seenFields := make(map[string]bool, len(e.Fields))
	for i := range e.Fields {
		f := &e.Fields[i]
		if f.Name == "" {
			return fmt.Errorf("manifest: entity %q: field name must not be empty", e.Name)
		}
		if seenFields[f.Name] {
			return fmt.Errorf("manifest: entity %q: duplicate field name %q", e.Name, f.Name)
		}
		seenFields[f.Name] = true
		if !f.Type.Valid() {
			return fmt.Errorf("manifest: entity %q: field %q: unrecognized field type %q", e.Name, f.Name, f.Type)
		}
		if f.PII != nil && !f.PII.Valid() {
			return fmt.Errorf("manifest: entity %q: field %q: unrecognized PII category %q", e.Name, f.Name, *f.PII)
		}
	}

	seenRels := make(map[string]bool, len(e.Relationships))
	for i := range e.Relationships {
		r := &e.Relationships[i]
		if r.Name == "" {
			return fmt.Errorf("manifest: entity %q: relationship name must not be empty", e.Name)
		}
		if seenRels[r.Name] {
			return fmt.Errorf("manifest: entity %q: duplicate relationship name %q", e.Name, r.Name)
		}
		seenRels[r.Name] = true
		if !r.Kind.Valid() {
			return fmt.Errorf("manifest: entity %q: relationship %q: unrecognized relationship kind %q", e.Name, r.Name, r.Kind)
		}
		if r.Target == "" {
			return fmt.Errorf("manifest: entity %q: relationship %q: target must not be empty", e.Name, r.Name)
		}
		if _, ok := m.Entity(r.Target); !ok {
			return fmt.Errorf("manifest: entity %q: relationship %q: target %q does not match any entity", e.Name, r.Name, r.Target)
		}
	}
	return nil
}
