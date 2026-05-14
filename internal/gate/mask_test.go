package gate

import (
	"testing"

	"github.com/bensyverson/kura/internal/pii"
)

func visibleSet(cats ...pii.Category) map[pii.Category]bool {
	s := make(map[pii.Category]bool, len(cats))
	for _, c := range cats {
		s[c] = true
	}
	return s
}

func TestRedactValueLeavesAVisibleSpanInPlace(t *testing.T) {
	value := "Jane Doe"
	spans := []pii.Span{{Category: pii.CategoryPerson, Offset: 0, Length: 8}}
	got := redactValue(value, spans, visibleSet(pii.CategoryPerson))
	if got != "Jane Doe" {
		t.Errorf("redactValue = %q, want %q", got, "Jane Doe")
	}
}

func TestRedactValueRedactsANonVisibleSpan(t *testing.T) {
	value := "Jane Doe"
	spans := []pii.Span{{Category: pii.CategoryPerson, Offset: 0, Length: 8}}
	got := redactValue(value, spans, visibleSet())
	if got != Redacted {
		t.Errorf("redactValue = %q, want %q", got, Redacted)
	}
}

func TestRedactValueRedactsOnlyTheNonVisibleSpans(t *testing.T) {
	// "Jane Doe lives at 12 Oak St" — person visible, address not.
	value := "Jane Doe lives at 12 Oak St"
	spans := []pii.Span{
		{Category: pii.CategoryPerson, Offset: 0, Length: 8},
		{Category: pii.CategoryAddress, Offset: 18, Length: 9},
	}
	got := redactValue(value, spans, visibleSet(pii.CategoryPerson))
	want := "Jane Doe lives at " + Redacted
	if got != want {
		t.Errorf("redactValue = %q, want %q", got, want)
	}
}

func TestRedactValueWithNoSpansIsUnchanged(t *testing.T) {
	got := redactValue("nothing sensitive here", nil, visibleSet())
	if got != "nothing sensitive here" {
		t.Errorf("redactValue = %q, want unchanged", got)
	}
}

func TestRedactValueHandlesOverlappingSpans(t *testing.T) {
	// Two non-visible spans that overlap must not double-redact or panic.
	value := "abcdefghij"
	spans := []pii.Span{
		{Category: pii.CategoryPerson, Offset: 2, Length: 5},
		{Category: pii.CategoryPhone, Offset: 4, Length: 4},
	}
	got := redactValue(value, spans, visibleSet())
	want := "ab" + Redacted + "ij"
	if got != want {
		t.Errorf("redactValue = %q, want %q", got, want)
	}
}

func TestRedactValueIgnomesOutOfBoundsSpan(t *testing.T) {
	// A span whose range runs past the value must be clamped, not panic.
	value := "short"
	spans := []pii.Span{{Category: pii.CategoryPerson, Offset: 2, Length: 999}}
	got := redactValue(value, spans, visibleSet())
	want := "sh" + Redacted
	if got != want {
		t.Errorf("redactValue = %q, want %q", got, want)
	}
}
