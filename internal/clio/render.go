package clio

import (
	"encoding/json"
	"io"
)

// Format selects the output format for Render. Markdown is the
// documented default; JSON is opt-in. New formats are deliberately
// not added — see the design guidelines on the cost of CLI surface
// drift.
type Format string

const (
	// FormatMarkdown is dense Markdown — the default human-and-agent
	// readable shape. Empty Format is treated as Markdown so callers
	// don't have to spell it out.
	FormatMarkdown Format = "md"

	// FormatJSON is indented JSON — opt-in for deterministic parsers.
	FormatJSON Format = "json"
)

// Render writes v to out in the requested format. The CLI uses this
// from every command's RunE so all output flows through one path —
// that is what makes the masking-invariance guarantee testable.
//
//   - For FormatJSON, Render emits v as indented JSON.
//   - For FormatMarkdown (or the empty default), Render invokes the
//     caller-supplied markdown closure, which is free to format
//     however the verb's audience expects.
//
// markdown is a closure rather than an interface method because Kura
// renders existing core types (identity.Principal, future
// data.Record) for which adding presentation methods would couple the
// core to the CLI's output choices. The closure lets cmd/ own the
// Markdown shape while the core owns the data shape.
//
// An unknown format is a usage error — the agent passed something
// neither human-readable nor machine-readable, and a silent fallback
// would hide the misconfiguration.
func Render(out io.Writer, format Format, v any, markdown func(io.Writer) error) error {
	switch format {
	case FormatJSON:
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	case FormatMarkdown, "":
		return markdown(out)
	default:
		return UsageError("", "unknown output format %q (use one of: md, json)", string(format))
	}
}
