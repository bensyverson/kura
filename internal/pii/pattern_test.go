package pii

import (
	"context"
	"testing"
)

func TestPatternDetectorDetectsRegisteredPattern(t *testing.T) {
	const text = "reach me at alice@example.com please"
	d := NewPatternDetector().MustRegister(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`, CategoryEmail)

	spans, err := d.Detect(context.Background(), text)
	if err != nil {
		t.Fatal(err)
	}
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d: %+v", len(spans), spans)
	}
	s := spans[0]
	if s.Category != CategoryEmail {
		t.Errorf("category = %q, want %q", s.Category, CategoryEmail)
	}
	if got := text[s.Offset : s.Offset+s.Length]; got != "alice@example.com" {
		t.Errorf("span points at %q, want the email", got)
	}
	if s.Confidence != 1.0 {
		t.Errorf("confidence = %v, want 1.0", s.Confidence)
	}
}

func TestPatternDetectorFindsMultipleOccurrences(t *testing.T) {
	d := NewPatternDetector().MustRegister(`\bsecret\b`, CategorySecret)
	spans, err := d.Detect(context.Background(), "one secret then another secret")
	if err != nil {
		t.Fatal(err)
	}
	if len(spans) != 2 {
		t.Fatalf("expected 2 spans, got %d", len(spans))
	}
}

func TestPatternDetectorNoMatch(t *testing.T) {
	d := NewPatternDetector().MustRegister(`\d{3}-\d{2}-\d{4}`, CategoryAccountNumber)
	spans, err := d.Detect(context.Background(), "nothing sensitive here")
	if err != nil {
		t.Fatal(err)
	}
	if len(spans) != 0 {
		t.Errorf("expected no spans, got %d", len(spans))
	}
}

func TestDefaultPatternDetectorSpansEveryCategory(t *testing.T) {
	const text = "email ada@example.com phone 555-867-5309 ssn 123-45-6789"
	spans, err := DefaultPatternDetector().Detect(context.Background(), text)
	if err != nil {
		t.Fatal(err)
	}

	got := make(map[Category]string)
	for _, s := range spans {
		got[s.Category] = text[s.Offset : s.Offset+s.Length]
	}
	if got[CategoryEmail] != "ada@example.com" {
		t.Errorf("email span = %q, want %q", got[CategoryEmail], "ada@example.com")
	}
	if got[CategoryPhone] != "555-867-5309" {
		t.Errorf("phone span = %q, want %q", got[CategoryPhone], "555-867-5309")
	}
	// An SSN is a high-sensitivity account_number: it must be detected so the
	// gate encrypts it at rest and masks it for non-admins.
	if got[CategoryAccountNumber] != "123-45-6789" {
		t.Errorf("account-number span = %q, want %q", got[CategoryAccountNumber], "123-45-6789")
	}
	if !CategoryAccountNumber.HighSensitivity() {
		t.Error("account_number should be high-sensitivity for the masking demo to work")
	}
}

func TestPatternDetectorRejectsUnrecognizedCategory(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("expected MustRegister to panic on an unrecognized category")
		}
	}()
	NewPatternDetector().MustRegister(`x`, Category("not_a_category"))
}
