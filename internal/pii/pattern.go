package pii

import (
	"context"
	"fmt"
	"regexp"
)

// PatternDetector is a regex-based Detector for development and offline
// use. It is not the production detector — the real ServiceDetector wraps
// the OpenAI Privacy Filter model — but it implements the same Detector
// contract over a handful of patterns, so a local Kura can scan, classify,
// and mask without standing up the model service. DefaultPatternDetector
// returns one wired for the common categories.
type PatternDetector struct {
	rules []patternRule
}

type patternRule struct {
	re       *regexp.Regexp
	category Category
}

var _ Detector = (*PatternDetector)(nil)

// NewPatternDetector returns a PatternDetector with no rules.
func NewPatternDetector() *PatternDetector { return &PatternDetector{} }

// MustRegister adds a rule mapping every match of pattern to category, and
// returns the detector so registrations can be chained. It panics on an
// uncompilable pattern or an unrecognized category — both are programmer
// errors fixed at the call site, like regexp.MustCompile.
func (d *PatternDetector) MustRegister(pattern string, category Category) *PatternDetector {
	if !category.Valid() {
		panic(fmt.Sprintf("pii: PatternDetector.MustRegister: unrecognized category %q", category))
	}
	d.rules = append(d.rules, patternRule{re: regexp.MustCompile(pattern), category: category})
	return d
}

// Detect reports a span for every match of every registered pattern, with
// full confidence — a pattern match is treated as a certain detection. The
// offsets are byte positions into text, matching the Span contract.
func (d *PatternDetector) Detect(_ context.Context, text string) ([]Span, error) {
	var spans []Span
	for _, r := range d.rules {
		for _, loc := range r.re.FindAllStringIndex(text, -1) {
			spans = append(spans, Span{
				Category:   r.category,
				Offset:     loc[0],
				Length:     loc[1] - loc[0],
				Confidence: 1.0,
			})
		}
	}
	return spans, nil
}

// DefaultPatternDetector returns a PatternDetector wired for the PII a
// dev instance is most likely to carry: email addresses, US-style phone
// numbers, and US Social Security numbers. SSNs map to account_number,
// the high-sensitivity category — so a seeded SSN is encrypted at rest and
// masked for non-admin readers, exercising the gate end to end.
func DefaultPatternDetector() *PatternDetector {
	return NewPatternDetector().
		MustRegister(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`, CategoryEmail).
		MustRegister(`\b\d{3}-\d{2}-\d{4}\b`, CategoryAccountNumber).
		MustRegister(`\b\d{3}-\d{3}-\d{4}\b`, CategoryPhone)
}
