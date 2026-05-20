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

// IngestRequest is one request to write a record through the gate.
type IngestRequest struct {
	// Token is the raw authentication token; the gate resolves it to a
	// principal.
	Token string
	// Entity names the manifest entity the record belongs to.
	Entity string
	// Fields is the record's raw field values, field-name to value.
	Fields map[string]string
}

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

// WriteRecord is the fully-decided record the gate hands its Writer: the
// classified fields and the spans detected at ingestion. It is the write
// analogue of the masked AccessResult — the gate's output, after every
// enforcement step, ready to persist.
type WriteRecord struct {
	Fields []WriteField
	Spans  []WriteSpan
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
// entity or undeclared field is refused before any data is persisted.
func (g *Gate) Ingest(ctx context.Context, req IngestRequest, write Writer) (IngestResult, error) {
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

	// 3. Validate: every incoming field is one the manifest declares.
	if err := validateFields(entity, req.Fields); err != nil {
		return IngestResult{}, err
	}

	// 4. Scan for PII — the ingestion-time scan, the counterpart to the
	// access-time re-scan that masking does.
	spansByField, err := g.scanner.ScanRecord(ctx, req.Fields)
	if err != nil {
		return IngestResult{}, fmt.Errorf("gate: scanning for ingestion: %w", err)
	}

	// 5. Classify each field's at-rest storage and assemble the record.
	rec := classifyRecord(entity, req.Fields, spansByField)

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
