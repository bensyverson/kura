// Package pii owns Kura's PII vocabulary. The Category enum is the shared
// language between the schema manifest (which declares a field's
// category), the PII detection layer (which detects categories in
// free-text), and the Cedar policy IR (which gates access per category).
package pii

import "slices"

// Category is a kind of personally identifiable information.
//
// Kura's v1 vocabulary mirrors the OpenAI Privacy Filter's detection
// categories, so a manifest tag and a detector output speak the same
// language with no translation layer. The enum is Kura-owned, not the
// detector's — adding a category later is a deliberate change here, not
// something forced by a dependency.
type Category string

const (
	CategoryAccountNumber Category = "account_number"
	CategoryAddress       Category = "private_address"
	CategoryEmail         Category = "private_email"
	CategoryPerson        Category = "private_person"
	CategoryPhone         Category = "private_phone"
	CategoryURL           Category = "private_url"
	CategoryDate          Category = "private_date"
	CategorySecret        Category = "secret"
)

// allCategories is the recognized set, in a stable order.
var allCategories = []Category{
	CategoryAccountNumber,
	CategoryAddress,
	CategoryEmail,
	CategoryPerson,
	CategoryPhone,
	CategoryURL,
	CategoryDate,
	CategorySecret,
}

// Categories returns every recognized PII category, in a stable order.
func Categories() []Category {
	out := make([]Category, len(allCategories))
	copy(out, allCategories)
	return out
}

// Valid reports whether c is a recognized PII category.
func (c Category) Valid() bool {
	return slices.Contains(allCategories, c)
}

// HighSensitivity reports whether c is sensitive enough to warrant
// field-level encryption (as opposed to category-based masking alone).
// v1: account numbers and secrets. The PII-detection task may refine
// this as the detector's behavior is verified.
func (c Category) HighSensitivity() bool {
	switch c {
	case CategoryAccountNumber, CategorySecret:
		return true
	default:
		return false
	}
}
