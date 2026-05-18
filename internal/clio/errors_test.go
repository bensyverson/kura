package clio

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Every typed constructor produces an *Error whose first line begins
// with `<verb>: ` — the greppable, machine-matchable prefix the CLI
// design guidelines pin as the agent-facing contract. If a constructor
// is added or changed in a way that breaks the prefix, this test fails.
//
// The pattern is the same shape as job's `...ErrorPrefixIsGreppable`
// regression tests: one row per typed constructor, one assertion on the
// stable prefix.
func TestCLIErrorPrefixIsGreppable(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"usage", UsageError("whoami", "--local requires --as <email>")},
		{"auth", AuthError("whoami", "no cached credential (run `kura login`)")},
		{"not-found", NotFoundError("user get", "no such user: alex@client.example")},
		{"conflict", ConflictError("user add", "alex@client.example already exists")},
		{"transient", TransientError("whoami", "server returned 503 (try again)")},
		{"internal", InternalError("whoami", "unexpected nil principal")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			line := c.err.Error()
			// First line is the greppable contract. Multi-line errors are
			// allowed but the agent must be able to match on the first.
			first := strings.SplitN(line, "\n", 2)[0]
			if !strings.HasPrefix(first, "whoami: ") &&
				!strings.HasPrefix(first, "user get: ") &&
				!strings.HasPrefix(first, "user add: ") {
				t.Errorf("first line %q does not start with `<verb>: `", first)
			}
		})
	}
}

// ExitCode maps every Kind to its documented exit code, and 0/1 fall
// out for the nil and non-typed cases. This is the taxonomy criterion
// (19J) — adding a Kind without updating ExitCode (or the docs) will
// trip this test.
func TestExitCodeTaxonomy(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"nil is success", nil, 0},
		{"unclassified is generic failure", errors.New("boom"), 1},
		{"usage", UsageError("v", "bad flag"), 2},
		{"auth", AuthError("v", "no creds"), 3},
		{"not-found", NotFoundError("v", "no row"), 4},
		{"conflict", ConflictError("v", "duplicate"), 5},
		{"transient", TransientError("v", "503"), 6},
		{"internal", InternalError("v", "nil deref"), 7},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ExitCode(c.err)
			if got != c.want {
				t.Errorf("ExitCode(%v) = %d, want %d", c.err, got, c.want)
			}
		})
	}
}

// A wrapped *Error keeps its Kind through errors.As — so a caller that
// wraps with %w preserves the taxonomy contract end-to-end.
func TestExitCodeUnwrapsWrappedError(t *testing.T) {
	inner := AuthError("whoami", "no cached credential")
	wrapped := fmt.Errorf("outer context: %w", inner)
	if got := ExitCode(wrapped); got != 3 {
		t.Errorf("ExitCode(wrapped auth) = %d, want 3", got)
	}
}

// The taxonomy must enumerate exactly the six documented kinds. Adding
// a new kind requires updating ExitCode, the docs page, and this list.
// The test catches a kind added without a code, and a code added without
// a kind.
func TestKindEnumerationIsComplete(t *testing.T) {
	all := AllKinds()
	want := map[Kind]int{
		KindUsage:     2,
		KindAuth:      3,
		KindNotFound:  4,
		KindConflict:  5,
		KindTransient: 6,
		KindInternal:  7,
	}
	if len(all) != len(want) {
		t.Fatalf("AllKinds() returned %d kinds, want %d — update both the taxonomy and the docs", len(all), len(want))
	}
	for _, k := range all {
		got := ExitCode(&Error{Kind: k, Verb: "v", Msg: "m"})
		if got != want[k] {
			t.Errorf("Kind %v -> ExitCode %d, want %d", k, got, want[k])
		}
	}
}

// Empty-verb errors are still readable — but a real CLI call should
// always supply one. Verb is the first half of the greppable prefix;
// dropping it loses the contract.
func TestErrorWithEmptyVerbHasNoLeadingColon(t *testing.T) {
	e := &Error{Kind: KindInternal, Msg: "thing went wrong"}
	if got := e.Error(); got != "thing went wrong" {
		t.Errorf("Error() = %q, want %q", got, "thing went wrong")
	}
}
