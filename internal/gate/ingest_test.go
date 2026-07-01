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

// ingestManifest declares a patient whose fields span the encrypt-by-default
// boundary (D2): content types (string, text) encrypt regardless of PII
// tagging, while structural types (integer, boolean, timestamp) stay
// plaintext. full_name (low-sensitivity PII) and nickname (untagged) prove
// that content encrypts independent of any sensitivity judgment; visit_count,
// active, and admitted_at prove the structural opt-out.
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
				{Name: "visit_count", Type: manifest.FieldInteger},
				{Name: "active", Type: manifest.FieldBoolean},
				{Name: "admitted_at", Type: manifest.FieldTimestamp},
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

// storedEncrypted is type-driven (D2): content fields (string, text) encrypt
// by default and structural fields (integer, boolean, timestamp) stay
// plaintext — the opt-out is the type, never a sensitivity judgment, so a
// no-PII string and a high-sensitivity string both encrypt.
func TestStoredEncryptedIsTypeDriven(t *testing.T) {
	cases := []struct {
		name  string
		field manifest.Field
		want  bool
	}{
		{"plain string encrypts", manifest.Field{Type: manifest.FieldString}, true},
		{"high-sensitivity string encrypts", manifest.Field{Type: manifest.FieldString, PII: new(pii.CategoryAccountNumber)}, true},
		{"free text encrypts", manifest.Field{Type: manifest.FieldText}, true},
		{"integer stays plaintext", manifest.Field{Type: manifest.FieldInteger}, false},
		{"boolean stays plaintext", manifest.Field{Type: manifest.FieldBoolean}, false},
		{"timestamp stays plaintext", manifest.Field{Type: manifest.FieldTimestamp}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := storedEncrypted(tc.field); got != tc.want {
				t.Errorf("storedEncrypted(%s) = %v, want %v", tc.field.Type, got, tc.want)
			}
		})
	}
}

// End to end, the gate encrypts content fields by default and leaves only
// structural fields plaintext: account/notes/full_name/nickname (string and
// text) all encrypt — full_name and nickname included, proving the decision
// is decoupled from sensitivity — while visit_count/active/admitted_at
// (integer, boolean, timestamp) stay plaintext.
func TestIngestEncryptsContentFieldsByDefault(t *testing.T) {
	detector := pii.NewFakeDetector().Register("Jane Doe", pii.CategoryPerson, 0.99)
	h := newIngestHarness(t, detector)
	tok := h.token(t, "alice", "admin")
	write, got := captureWriter("rec-1")

	_, err := h.gate.Ingest(context.Background(), IngestRequest{
		Token:  tok,
		Entity: "patient",
		Fields: map[string]string{
			"full_name":   "Jane Doe",
			"account":     "ACCT-555",
			"notes":       "no pii here",
			"nickname":    "JD",
			"visit_count": "3",
			"active":      "true",
			"admitted_at": "2026-01-02T15:04:05Z",
		},
	}, existsNone, write)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	rec := *got
	cases := map[string]bool{
		"account": true, "notes": true, "full_name": true, "nickname": true,
		"visit_count": false, "active": false, "admitted_at": false,
	}
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
