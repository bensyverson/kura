package pii

import "context"

// Scanner runs a Detector at Kura's two PII call sites:
//
//   - INGESTION: every free-text field is scanned and the detected spans
//     stored as structured metadata alongside the source text.
//   - ACCESS TIME: free-text is re-scanned to decide category-based
//     masking — catching detector drift if the model improves between
//     when the data was ingested and when it is read.
type Scanner struct {
	d Detector
}

// NewScanner returns a Scanner backed by d.
func NewScanner(d Detector) *Scanner { return &Scanner{d: d} }

// ScanRecord is the ingestion call site. fields maps a free-text field's
// name to its value; the caller — which knows the manifest — passes only
// the free-text fields. The result is the detected spans per field,
// ready to store as the record's PII metadata.
func (s *Scanner) ScanRecord(ctx context.Context, fields map[string]string) (map[string][]Span, error) {
	out := make(map[string][]Span, len(fields))
	for name, text := range fields {
		spans, err := s.d.Detect(ctx, text)
		if err != nil {
			return nil, err
		}
		out[name] = spans
	}
	return out, nil
}

// DetectCategories is the access-time call site. It re-scans text and
// returns the distinct PII categories present, in the canonical category
// order — exactly the input cedar's evaluator needs to decide
// category-based masking.
func (s *Scanner) DetectCategories(ctx context.Context, text string) ([]Category, error) {
	spans, err := s.d.Detect(ctx, text)
	if err != nil {
		return nil, err
	}
	present := make(map[Category]bool, len(spans))
	for _, sp := range spans {
		present[sp.Category] = true
	}
	var out []Category
	for _, c := range allCategories {
		if present[c] {
			out = append(out, c)
		}
	}
	return out, nil
}
