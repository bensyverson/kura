package pii

import "testing"

func TestCategoriesAreAllValid(t *testing.T) {
	for _, c := range Categories() {
		if !c.Valid() {
			t.Errorf("Categories() returned %q but Valid() rejects it", c)
		}
	}
}

func TestUnrecognizedCategoryIsInvalid(t *testing.T) {
	for _, c := range []Category{"social_security", "", "PRIVATE_EMAIL", "name"} {
		if c.Valid() {
			t.Errorf("Category(%q) reported as valid", c)
		}
	}
}

// v1 vocabulary mirrors the OpenAI Privacy Filter's detection categories,
// so a manifest tag and a detector output speak the same language.
func TestCategoryCountMatchesDetectorVocabulary(t *testing.T) {
	if got := len(Categories()); got != 8 {
		t.Errorf("expected 8 PII categories, got %d", got)
	}
}

func TestHighSensitivitySubset(t *testing.T) {
	high := map[Category]bool{
		CategoryAccountNumber: true,
		CategorySecret:        true,
	}
	for _, c := range Categories() {
		if got := c.HighSensitivity(); got != high[c] {
			t.Errorf("%q HighSensitivity() = %v, want %v", c, got, high[c])
		}
	}
}
