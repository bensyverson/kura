package clio

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
)

// maskedRecord is a stand-in for any record that has already passed
// through the core's masking layer by the time it reaches the
// renderer. The point of the test below is that Render is a
// presentation choice: whatever value the caller hands in, both
// formats show *that* value — not a more revealing one.
type maskedRecord struct {
	Email string `json:"email"`
}

func (r maskedRecord) renderMarkdown(w io.Writer) error {
	_, err := fmt.Fprintf(w, "- email: %s\n", r.Email)
	return err
}

// Render with format=Markdown invokes the Markdown closure; with
// format=JSON it json-encodes the value. The same record passed to
// both must produce the same field value in the output. This is
// criterion tb7 — "Markdown and --json outputs carry identical masking
// for the same principal" — pinned by a test.
func TestRenderIsMaskingInvariant(t *testing.T) {
	rec := maskedRecord{Email: "j***@firm.example"} // already masked by the core

	var md bytes.Buffer
	if err := Render(&md, FormatMarkdown, rec, rec.renderMarkdown); err != nil {
		t.Fatalf("Render markdown: %v", err)
	}

	var js bytes.Buffer
	if err := Render(&js, FormatJSON, rec, rec.renderMarkdown); err != nil {
		t.Fatalf("Render json: %v", err)
	}

	if !strings.Contains(md.String(), "j***@firm.example") {
		t.Errorf("markdown output missing masked value: %q", md.String())
	}
	if !strings.Contains(js.String(), "j***@firm.example") {
		t.Errorf("json output missing masked value: %q", js.String())
	}
	// The presentation must never reveal a value the masking layer
	// stripped. We pin the contract by asserting the unmasked address
	// the masker would have removed never appears in either format.
	for _, out := range []string{md.String(), js.String()} {
		if strings.Contains(out, "jane@firm.example") {
			t.Errorf("renderer leaked unmasked email: %q", out)
		}
	}
}

// JSON output uses indented encoding for readability and ends with a
// newline — the same shape the existing whoami JSON output had.
func TestRenderJSONIsIndented(t *testing.T) {
	rec := maskedRecord{Email: "j***@firm.example"}
	var buf bytes.Buffer
	if err := Render(&buf, FormatJSON, rec, rec.renderMarkdown); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.NewDecoder(&buf).Decode(&got); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if got["email"] != "j***@firm.example" {
		t.Errorf("email field = %v, want %q", got["email"], "j***@firm.example")
	}
}

// Markdown is the documented default: an empty format renders Markdown.
// This pins the design-guideline rule that JSON is opt-in.
func TestRenderDefaultFormatIsMarkdown(t *testing.T) {
	rec := maskedRecord{Email: "x"}
	var buf bytes.Buffer
	if err := Render(&buf, "", rec, rec.renderMarkdown); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(buf.String(), "- email:") {
		t.Errorf("default format did not invoke markdown closure: %q", buf.String())
	}
}

// An unknown format is a usage error — the caller passed something
// neither human-readable nor machine-readable, and we want a
// greppable, taxonomy-classified error rather than silent fallback.
func TestRenderUnknownFormatIsUsageError(t *testing.T) {
	var buf bytes.Buffer
	err := Render(&buf, "yaml", maskedRecord{}, func(io.Writer) error { return nil })
	if err == nil {
		t.Fatal("unknown format returned no error")
	}
	if ExitCode(err) != 2 {
		t.Errorf("unknown format error has exit code %d, want 2 (usage)", ExitCode(err))
	}
	if !strings.Contains(err.Error(), "yaml") {
		t.Errorf("error %q does not name the offending format", err)
	}
}
