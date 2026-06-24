package gate

import (
	"context"
	"errors"
	"fmt"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/cedar"
	"github.com/bensyverson/kura/internal/identity"
	"github.com/bensyverson/kura/internal/manifest"
	"github.com/bensyverson/kura/internal/pii"
)

// ErrUnknownField is returned when an ingestion request carries a field
// the manifest does not declare for the entity. An undeclared field could
// never be read back through the gate (no policy reasons about it) and
// could smuggle unscanned data past the schema, so it is refused.
var ErrUnknownField = errors.New("gate: unknown field")

// ErrUnknownRelationship is returned when an ingestion request carries a
// relationship the manifest does not declare for the entity. Like an
// undeclared field, an undeclared relationship has no schema to validate it
// against and no policy reasoning about it, so it is refused.
var ErrUnknownRelationship = errors.New("gate: unknown relationship")

// ErrCardinality is returned when a relationship declared with "one"
// cardinality is given more than one target.
var ErrCardinality = errors.New("gate: relationship cardinality violated")

// ErrEdgeTarget is returned when a relationship's target record does not
// exist or is not of the relationship's declared target entity. Keying the
// existence check on the declared entity means a target of the wrong entity
// is indistinguishable from a missing one — both are simply absent.
var ErrEdgeTarget = errors.New("gate: relationship target not found")

// IngestRequest is one request to write a record through the gate.
type IngestRequest struct {
	// Token is the raw authentication token; the gate resolves it to a
	// principal.
	Token string
	// Entity names the manifest entity the record belongs to.
	Entity string
	// Fields is the record's raw field values, field-name to value.
	Fields map[string]string
	// Relationships is the record's relationship edges, keyed by the
	// relationship name the manifest declares on the entity, each mapping to
	// the ids of the target records it points at. A "one" relationship may
	// name at most one target; a "many" relationship may name several.
	Relationships map[string][]string
}

// RecordExists reports whether a record of the given entity and id exists.
// Like the Writer it is supplied by the adapter and is enforcement-blind:
// the gate uses it only to confirm a relationship's target exists and is of
// the declared target entity. It is keyed on entity so that a target of the
// wrong entity reports absent — one call settles both "no such record" and
// "wrong entity" — and so the gate need never hold a data-store dependency.
type RecordExists func(ctx context.Context, entity, id string) (bool, error)

// WriteField is one field the gate has decided to persist: its manifest
// type (for the storage layer's field_type), its value, and whether the
// value must be stored encrypted at rest.
type WriteField struct {
	Name      string
	Type      string
	Value     string
	Encrypted bool
}

// WriteSpan is one detected-PII span the gate found while scanning the
// record at ingestion, to be persisted as metadata alongside the record.
type WriteSpan struct {
	Field      string
	Category   pii.Category
	Offset     int
	Length     int
	Confidence float64
}

// WriteEdge is one validated relationship edge the gate hands its Writer:
// the relationship name (as declared on the source entity) and the id of the
// target record. The source is the record being written, so it is not named.
type WriteEdge struct {
	Relationship string
	TargetID     string
}

// WriteRecord is the fully-decided record the gate hands its Writer: the
// classified fields, the spans detected at ingestion, and the validated
// relationship edges. It is the write analogue of the masked AccessResult —
// the gate's output, after every enforcement step, ready to persist.
type WriteRecord struct {
	Fields        []WriteField
	Spans         []WriteSpan
	Relationships []WriteEdge
}

// Writer persists a record the gate has authorized, validated, scanned,
// and classified, returning the new record's id. Like a Fetcher it runs
// only after the gate's checks pass — so it cannot be a way around them —
// and it sees only what the gate decided to write.
type Writer func(ctx context.Context, rec WriteRecord) (string, error)

// IngestResult is what a caller gets back from a successful Ingest: the
// resolved principal and the new record's id.
type IngestResult struct {
	Principal identity.Principal
	RecordID  string
}

// Ingest runs the full enforcement chain for one write:
//
//	authenticate -> authorize(create) -> validate -> scan -> classify -> write -> audit
//
// Every step happens, in order, every time. The write callback supplies
// persistence but cannot be a way around the gate: it runs only after
// authorization, validation, and scanning pass, and only with the fields
// the gate classified. A denied request never reaches write; an unknown
// entity, undeclared field, or undeclared/invalid relationship is refused
// before any data is persisted. The exists callback resolves relationship
// targets during validation; it is never a way around the gate.
func (g *Gate) Ingest(ctx context.Context, req IngestRequest, exists RecordExists, write Writer) (IngestResult, error) {
	// 1. Authenticate.
	principal, err := g.authenticate(ctx, req.Token)
	if err != nil {
		return IngestResult{}, err
	}

	// 2. Authorize the create. authorize resolves the entity (returning
	// ErrUnknownEntity if the manifest does not declare it) and records the
	// decision; a denied create returns ErrDenied before any write.
	if _, err := g.authorize(ctx, principal, cedar.ActionCreate, req.Entity, ""); err != nil {
		return IngestResult{}, err
	}
	entity, _ := g.manifest.Entity(req.Entity) // present: authorize verified it

	// 3. Validate: every incoming field is one the manifest declares, and
	// every relationship is declared, within cardinality, and points at an
	// existing target of the declared entity.
	if err := validateFields(entity, req.Fields); err != nil {
		return IngestResult{}, err
	}
	edges, err := validateRelationships(ctx, entity, req.Relationships, exists)
	if err != nil {
		return IngestResult{}, err
	}

	// 4. Scan for PII — the ingestion-time scan, the counterpart to the
	// access-time re-scan that masking does.
	spansByField, err := g.scanner.ScanRecord(ctx, req.Fields)
	if err != nil {
		return IngestResult{}, fmt.Errorf("gate: scanning for ingestion: %w", err)
	}

	// 5. Classify each field's at-rest storage and assemble the record,
	// carrying the validated edges so the writer persists them with it.
	rec := classifyRecord(entity, req.Fields, spansByField)
	rec.Relationships = edges

	// 6. Write. The callback persists only what the gate classified.
	id, err := write(ctx, rec)
	if err != nil {
		return IngestResult{}, fmt.Errorf("gate: writing record: %w", err)
	}

	// 7. Audit the create against the new record's id.
	if err := g.recorder.RecordAccess(ctx, principal, string(cedar.ActionCreate), audit.Resource{Entity: req.Entity, ID: id}); err != nil {
		return IngestResult{}, fmt.Errorf("gate: recording ingestion: %w", err)
	}

	return IngestResult{Principal: principal, RecordID: id}, nil
}

// validateFields rejects any field the manifest does not declare for the
// entity. A field outside the schema has no policy reasoning about it and
// would never be readable through the gate, so admitting it would be a way
// to smuggle unscanned, unenforced data into the store.
func validateFields(e *manifest.Entity, fields map[string]string) error {
	declared := make(map[string]bool, len(e.Fields))
	for _, f := range e.Fields {
		declared[f.Name] = true
	}
	for name := range fields {
		if !declared[name] {
			return fmt.Errorf("%w: %q on entity %q", ErrUnknownField, name, e.Name)
		}
	}
	return nil
}

// validateRelationships checks each requested relationship against the
// entity's manifest and the existing records, returning the validated edges
// for the writer in manifest order. A relationship must be declared on the
// entity; a "one" relationship may name at most one target; and every target
// must exist and be of the relationship's declared target entity (the exists
// check is keyed on that entity, so a wrong-entity target is rejected the
// same as a missing one). Edges are produced in manifest order so the written
// record is deterministic regardless of request map iteration order.
func validateRelationships(ctx context.Context, e *manifest.Entity, rels map[string][]string, exists RecordExists) ([]WriteEdge, error) {
	if len(rels) == 0 {
		return nil, nil
	}
	declared := make(map[string]bool, len(e.Relationships))
	for _, r := range e.Relationships {
		declared[r.Name] = true
	}
	// Reject any undeclared relationship up front, before consulting the
	// store — an undeclared relationship has no schema to validate against.
	for name := range rels {
		if !declared[name] {
			return nil, fmt.Errorf("%w: %q on entity %q", ErrUnknownRelationship, name, e.Name)
		}
	}
	var edges []WriteEdge
	for _, r := range e.Relationships {
		targets, ok := rels[r.Name]
		if !ok {
			continue
		}
		if r.Kind == manifest.RelationshipOne && len(targets) > 1 {
			return nil, fmt.Errorf("%w: relationship %q on entity %q is one but names %d targets", ErrCardinality, r.Name, e.Name, len(targets))
		}
		for _, id := range targets {
			present, err := exists(ctx, r.Target, id)
			if err != nil {
				return nil, fmt.Errorf("gate: resolving relationship target: %w", err)
			}
			if !present {
				return nil, fmt.Errorf("%w: relationship %q target %q is not an existing %q", ErrEdgeTarget, r.Name, id, r.Target)
			}
			edges = append(edges, WriteEdge{Relationship: r.Name, TargetID: id})
		}
	}
	return edges, nil
}

// classifyRecord turns the validated raw fields plus the scan results into
// the record the writer persists. Fields are emitted in manifest order
// (stable storage), each carrying its type and an encryption decision; the
// detected spans follow, in the same order.
func classifyRecord(e *manifest.Entity, fields map[string]string, spansByField map[string][]pii.Span) WriteRecord {
	var rec WriteRecord
	for _, f := range e.Fields {
		val, ok := fields[f.Name]
		if !ok {
			continue
		}
		rec.Fields = append(rec.Fields, WriteField{
			Name:      f.Name,
			Type:      string(f.Type),
			Value:     val,
			Encrypted: storedEncrypted(f, spansByField[f.Name]),
		})
	}
	for _, f := range e.Fields {
		for _, sp := range spansByField[f.Name] {
			rec.Spans = append(rec.Spans, WriteSpan{
				Field:      f.Name,
				Category:   sp.Category,
				Offset:     sp.Offset,
				Length:     sp.Length,
				Confidence: sp.Confidence,
			})
		}
	}
	return rec
}

// storedEncrypted decides whether a field's value is stored encrypted at
// rest. A value warrants field-level encryption when it is free-text
// (which can hold anything), when the manifest declares it a
// high-sensitivity category, or when the ingestion scan detected a
// high-sensitivity category in it — the last catching PII the schema
// author did not anticipate in an otherwise-plain field.
func storedEncrypted(f manifest.Field, spans []pii.Span) bool {
	if f.Type == manifest.FieldText {
		return true
	}
	if f.PII != nil && f.PII.HighSensitivity() {
		return true
	}
	for _, sp := range spans {
		if sp.Category.HighSensitivity() {
			return true
		}
	}
	return false
}
