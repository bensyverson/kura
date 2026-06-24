package gate

import (
	"context"
	"errors"
	"testing"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/cedar"
	"github.com/bensyverson/kura/internal/identity"
	"github.com/bensyverson/kura/internal/manifest"
	"github.com/bensyverson/kura/internal/pii"
)

// ingestManifest declares a patient with: a person name (low-sensitivity
// PII), an account number (high-sensitivity PII), a free-text notes field,
// and an untagged nickname. The four fields exercise every encryption
// rule: declared high-sensitivity, free-text, scanner-detected, and none.
func ingestManifest() *manifest.Manifest {
	return &manifest.Manifest{
		Version: "1",
		Entities: []manifest.Entity{{
			Name: "patient",
			Fields: []manifest.Field{
				{Name: "full_name", Type: manifest.FieldString, PII: new(pii.CategoryPerson)},
				{Name: "account", Type: manifest.FieldString, PII: new(pii.CategoryAccountNumber)},
				{Name: "notes", Type: manifest.FieldText},
				{Name: "nickname", Type: manifest.FieldString},
			},
		}},
	}
}

// newIngestHarness builds a gate over ingestManifest with a configurable
// detector, mirroring newHarness.
func newIngestHarness(t *testing.T, detector *pii.FakeDetector) *harness {
	t.Helper()
	m := ingestManifest()
	evaluator, err := cedar.NewEvaluator(cedar.DefaultPolicy(m))
	if err != nil {
		t.Fatalf("building evaluator: %v", err)
	}
	auth := identity.NewAuthenticator([]byte("test-signing-secret"))
	roles := NewMapRoleResolver()
	store := audit.NewMemStore()
	g, err := New(auth, evaluator, roles, m, pii.NewScanner(detector), audit.NewRecorder(store))
	if err != nil {
		t.Fatalf("New gate: %v", err)
	}
	return &harness{gate: g, auth: auth, roles: roles, store: store, detector: detector}
}

// captureWriter returns a Writer that records the WriteRecord it was given
// and reports a fixed id, plus a pointer to the captured record (nil until
// the writer runs, so a test can assert the writer was never reached).
func captureWriter(id string) (Writer, **WriteRecord) {
	var got *WriteRecord
	w := func(_ context.Context, rec WriteRecord) (string, error) {
		r := rec
		got = &r
		return id, nil
	}
	return w, &got
}

// existsNone is a RecordExists that reports every target absent. The
// field-classification tests carry no relationships, so it is never
// consulted; it only satisfies Ingest's signature.
func existsNone(_ context.Context, _, _ string) (bool, error) { return false, nil }

// existsSet returns a RecordExists that reports a target present exactly when
// its (entity, id) pair is in the set. It lets a test stand in for the store
// without one, including the wrong-entity case: an id present under one
// entity reports absent under another.
func existsSet(pairs ...[2]string) RecordExists {
	set := make(map[[2]string]bool, len(pairs))
	for _, p := range pairs {
		set[p] = true
	}
	return func(_ context.Context, entity, id string) (bool, error) {
		return set[[2]string{entity, id}], nil
	}
}

// fieldByName finds a classified field in a WriteRecord.
func fieldByName(rec *WriteRecord, name string) (WriteField, bool) {
	for _, f := range rec.Fields {
		if f.Name == name {
			return f, true
		}
	}
	return WriteField{}, false
}

// Ingest runs the full chain for an authorized admin: it returns the new
// id, audits authentication -> authorization -> access (create), and hands
// the writer the classified record.
func TestIngestRunsTheFullChainForAnAuthorizedAdmin(t *testing.T) {
	detector := pii.NewFakeDetector().
		Register("Jane Doe", pii.CategoryPerson, 0.99).
		Register("ACCT-555", pii.CategoryAccountNumber, 0.99)
	h := newIngestHarness(t, detector)
	tok := h.token(t, "alice", "admin")
	write, got := captureWriter("rec-1")

	res, err := h.gate.Ingest(context.Background(), IngestRequest{
		Token:  tok,
		Entity: "patient",
		Fields: map[string]string{"full_name": "Jane Doe", "account": "ACCT-555"},
	}, existsNone, write)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if res.RecordID != "rec-1" {
		t.Errorf("RecordID = %q, want rec-1", res.RecordID)
	}
	if res.Principal.ID != "alice" {
		t.Errorf("Principal.ID = %q, want alice", res.Principal.ID)
	}
	if *got == nil {
		t.Fatal("writer was never called")
	}
	kinds := eventKinds(t, h.store)
	want := []audit.Kind{audit.KindAuthentication, audit.KindAuthorization, audit.KindAccess}
	if len(kinds) != 3 || kinds[0] != want[0] || kinds[1] != want[1] || kinds[2] != want[2] {
		t.Errorf("audit kinds = %v, want %v", kinds, want)
	}
}

// The gate classifies which fields are stored encrypted: a declared
// high-sensitivity field (account) and a free-text field (notes) are
// encrypted; a low-sensitivity declared field (full_name) and a plain
// untagged field with no detected PII (nickname) are not.
func TestIngestClassifiesEncryptionFromTheManifest(t *testing.T) {
	detector := pii.NewFakeDetector().Register("Jane Doe", pii.CategoryPerson, 0.99)
	h := newIngestHarness(t, detector)
	tok := h.token(t, "alice", "admin")
	write, got := captureWriter("rec-1")

	_, err := h.gate.Ingest(context.Background(), IngestRequest{
		Token:  tok,
		Entity: "patient",
		Fields: map[string]string{
			"full_name": "Jane Doe",
			"account":   "ACCT-555",
			"notes":     "no pii here",
			"nickname":  "JD",
		},
	}, existsNone, write)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	rec := *got
	cases := map[string]bool{"account": true, "notes": true, "full_name": false, "nickname": false}
	for name, wantEnc := range cases {
		f, ok := fieldByName(rec, name)
		if !ok {
			t.Errorf("field %q missing from WriteRecord", name)
			continue
		}
		if f.Encrypted != wantEnc {
			t.Errorf("field %q Encrypted = %v, want %v", name, f.Encrypted, wantEnc)
		}
	}
}

// Scanner-detected high-sensitivity PII in a field the manifest did not tag
// forces that field to be stored encrypted — defense against PII landing in
// a plaintext column the schema author did not expect.
func TestIngestEncryptsScannerDetectedHighSensitivity(t *testing.T) {
	detector := pii.NewFakeDetector().Register("SECRET-XYZ", pii.CategorySecret, 0.97)
	h := newIngestHarness(t, detector)
	tok := h.token(t, "alice", "admin")
	write, got := captureWriter("rec-1")

	_, err := h.gate.Ingest(context.Background(), IngestRequest{
		Token:  tok,
		Entity: "patient",
		Fields: map[string]string{"nickname": "SECRET-XYZ"},
	}, existsNone, write)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	f, ok := fieldByName(*got, "nickname")
	if !ok {
		t.Fatal("nickname missing from WriteRecord")
	}
	if !f.Encrypted {
		t.Error("nickname holding a detected secret was not stored encrypted")
	}
}

// Detected spans are carried to the writer as ingestion metadata.
func TestIngestCarriesDetectedSpans(t *testing.T) {
	detector := pii.NewFakeDetector().Register("Jane Doe", pii.CategoryPerson, 0.99)
	h := newIngestHarness(t, detector)
	tok := h.token(t, "alice", "admin")
	write, got := captureWriter("rec-1")

	_, err := h.gate.Ingest(context.Background(), IngestRequest{
		Token:  tok,
		Entity: "patient",
		Fields: map[string]string{"full_name": "Jane Doe"},
	}, existsNone, write)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	rec := *got
	if len(rec.Spans) != 1 {
		t.Fatalf("Spans = %d, want 1", len(rec.Spans))
	}
	if rec.Spans[0].Field != "full_name" || rec.Spans[0].Category != pii.CategoryPerson {
		t.Errorf("span = {field:%q category:%q}, want {full_name private_person}", rec.Spans[0].Field, rec.Spans[0].Category)
	}
}

// A principal whose role cannot create is denied: Ingest returns ErrDenied,
// the writer is never reached, and the denial is audited.
func TestIngestDeniesARoleThatCannotCreate(t *testing.T) {
	h := newIngestHarness(t, pii.NewFakeDetector())
	tok := h.token(t, "ron", "auditor")
	write, got := captureWriter("rec-1")

	_, err := h.gate.Ingest(context.Background(), IngestRequest{
		Token:  tok,
		Entity: "patient",
		Fields: map[string]string{"full_name": "Jane Doe"},
	}, existsNone, write)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("Ingest err = %v, want ErrDenied", err)
	}
	if *got != nil {
		t.Error("writer was reached for a denied request")
	}
}

// An unknown entity is refused before any write.
func TestIngestRejectsUnknownEntity(t *testing.T) {
	h := newIngestHarness(t, pii.NewFakeDetector())
	tok := h.token(t, "alice", "admin")
	write, got := captureWriter("rec-1")

	_, err := h.gate.Ingest(context.Background(), IngestRequest{
		Token:  tok,
		Entity: "ghost",
		Fields: map[string]string{"full_name": "Jane Doe"},
	}, existsNone, write)
	if !errors.Is(err, ErrUnknownEntity) {
		t.Fatalf("Ingest err = %v, want ErrUnknownEntity", err)
	}
	if *got != nil {
		t.Error("writer was reached for an unknown entity")
	}
}

// A field the manifest does not declare is refused before any write — an
// undeclared field could smuggle unscanned, unreadable data past the schema.
func TestIngestRejectsUnknownField(t *testing.T) {
	h := newIngestHarness(t, pii.NewFakeDetector())
	tok := h.token(t, "alice", "admin")
	write, got := captureWriter("rec-1")

	_, err := h.gate.Ingest(context.Background(), IngestRequest{
		Token:  tok,
		Entity: "patient",
		Fields: map[string]string{"full_name": "Jane Doe", "ssn": "123-45-6789"},
	}, existsNone, write)
	if !errors.Is(err, ErrUnknownField) {
		t.Fatalf("Ingest err = %v, want ErrUnknownField", err)
	}
	if *got != nil {
		t.Error("writer was reached for an unknown field")
	}
}
