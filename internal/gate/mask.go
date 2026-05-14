package gate

import (
	"sort"
	"strings"

	"github.com/bensyverson/kura/internal/pii"
)

// Redacted is the constant a masked PII span is replaced with. It is a
// fixed string, identical for every caller — the API, the CLI, the
// dashboard, and the MCP server all see the same masked output because
// masking happens here, in the gate, not in any adapter.
const Redacted = "[redacted]"

// redactValue returns value with every PII span whose category is not in
// visible replaced by Redacted. Overlapping and adjacent hidden spans
// merge into one redaction. A span with a bad offset or length — past
// the end of value, or negative — is clamped, never panicked on: a
// detector reporting a malformed span must not take down the gate.
func redactValue(value string, spans []pii.Span, visible map[pii.Category]bool) string {
	var hidden []pii.Span
	for _, s := range spans {
		if !visible[s.Category] {
			hidden = append(hidden, s)
		}
	}
	if len(hidden) == 0 {
		return value
	}
	sort.Slice(hidden, func(i, j int) bool { return hidden[i].Offset < hidden[j].Offset })

	// Merge the hidden spans into non-overlapping byte intervals.
	type interval struct{ start, end int }
	var merged []interval
	for _, s := range hidden {
		start, end := s.Offset, s.Offset+s.Length
		if start < 0 {
			start = 0
		}
		if end > len(value) {
			end = len(value)
		}
		if start >= end {
			continue
		}
		if n := len(merged); n > 0 && start <= merged[n-1].end {
			if end > merged[n-1].end {
				merged[n-1].end = end
			}
			continue
		}
		merged = append(merged, interval{start, end})
	}

	var b strings.Builder
	cursor := 0
	for _, m := range merged {
		b.WriteString(value[cursor:m.start])
		b.WriteString(Redacted)
		cursor = m.end
	}
	b.WriteString(value[cursor:])
	return b.String()
}

// maskFields redacts every field value against its detected spans,
// leaving only the PII categories the authorization decision made
// visible. A field with no detected spans passes through unchanged.
func maskFields(spansByField map[string][]pii.Span, fields map[string]string, visible map[pii.Category]bool) map[string]string {
	out := make(map[string]string, len(fields))
	for name, value := range fields {
		out[name] = redactValue(value, spansByField[name], visible)
	}
	return out
}
