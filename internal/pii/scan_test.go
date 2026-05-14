package pii

import (
	"context"
	"testing"
)

// zlI: the ingestion call site produces category/offset/length/confidence
// metadata for the free-text fields it is given.
func TestScanRecordProducesPerFieldMetadata(t *testing.T) {
	d := NewFakeDetector().
		Register("alice@example.com", CategoryEmail, 0.95).
		Register("555-0100", CategoryPhone, 0.9)
	s := NewScanner(d)

	fields := map[string]string{
		"notes": "reach alice@example.com or call 555-0100",
		"memo":  "nothing here",
	}
	got, err := s.ScanRecord(context.Background(), fields)
	if err != nil {
		t.Fatal(err)
	}
	if len(got["notes"]) != 2 {
		t.Fatalf("notes: expected 2 spans, got %d", len(got["notes"]))
	}
	if len(got["memo"]) != 0 {
		t.Errorf("memo: expected 0 spans, got %d", len(got["memo"]))
	}
	for _, sp := range got["notes"] {
		if !sp.Category.Valid() || sp.Length == 0 || sp.Confidence == 0 {
			t.Errorf("span is missing metadata: %+v", sp)
		}
	}
}

// D8k: the access-time call site is invokable for category-based masking
// — it yields the distinct PII categories present, the input cedar's
// evaluator needs.
func TestScannerDetectCategories(t *testing.T) {
	d := NewFakeDetector().
		Register("alice@example.com", CategoryEmail, 1).
		Register("bob@example.com", CategoryEmail, 1).
		Register("4111111111111111", CategoryAccountNumber, 1)
	s := NewScanner(d)

	cats, err := s.DetectCategories(context.Background(), "alice@example.com, bob@example.com, 4111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	if len(cats) != 2 {
		t.Fatalf("expected 2 distinct categories, got %d: %v", len(cats), cats)
	}
	seen := map[Category]bool{}
	for _, c := range cats {
		if seen[c] {
			t.Errorf("category %q repeated — categories must be distinct", c)
		}
		seen[c] = true
	}
	if !seen[CategoryEmail] || !seen[CategoryAccountNumber] {
		t.Errorf("missing expected categories: %v", cats)
	}
}
