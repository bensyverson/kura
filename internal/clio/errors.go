package clio

import (
	"errors"
	"fmt"
)

// Kind classifies a CLI error so an agent can act on it without
// scraping prose. The set is closed: every error returned by a kura
// command resolves to exactly one Kind, and that Kind drives the exit
// code via ExitCode. New kinds must be added to AllKinds, ExitCode,
// and the docs (machine-interface/cli-output.md) together.
type Kind int

const (
	// kindUnspecified is the zero value. It exists so the AllKinds /
	// ExitCode helpers can tell "no Kind set" from "Kind = Usage" — a
	// safety net for the typed constructors, not a value callers pick.
	kindUnspecified Kind = iota

	// KindUsage — the input was wrong: a bad flag, a missing argument,
	// a value outside an enumerated set. Exit code 2.
	KindUsage

	// KindAuth — the caller is not authenticated, or is authenticated
	// but is not authorized for the requested action. Exit code 3.
	KindAuth

	// KindNotFound — the requested resource does not exist. Exit code 4.
	KindNotFound

	// KindConflict — the requested state change conflicts with current
	// state (already exists, precondition failed, ledger contention).
	// Exit code 5.
	KindConflict

	// KindTransient — the operation failed for a reason that may
	// succeed on retry (network blip, 5xx, lock contention upstream).
	// Exit code 6.
	KindTransient

	// KindInternal — an unexpected condition inside Kura itself.
	// Treat as a bug report, not a retry target. Exit code 7.
	KindInternal
)

// AllKinds returns the closed set of error kinds in canonical order.
// Tests use it to assert the taxonomy is complete; callers should
// prefer the typed constructors below.
func AllKinds() []Kind {
	return []Kind{KindUsage, KindAuth, KindNotFound, KindConflict, KindTransient, KindInternal}
}

// Error is a CLI error carrying its Kind and the verb that produced
// it. The Error string is `<verb>: <message>` — the greppable,
// machine-matchable first-line prefix the design guidelines pin as
// the agent-facing contract.
type Error struct {
	Kind  Kind
	Verb  string
	Msg   string
	Cause error
}

// Error returns the formatted message. An empty Verb is allowed but
// loses the greppable prefix — real CLI call sites always supply one.
func (e *Error) Error() string {
	if e.Verb == "" {
		return e.Msg
	}
	return e.Verb + ": " + e.Msg
}

// Unwrap returns the wrapped cause, if any, so errors.Is / errors.As
// traverse a chain like `clio.AuthError(... %w ..., cause)`.
func (e *Error) Unwrap() error { return e.Cause }

// UsageError reports invalid input. It is the most common kind: a
// missing flag, a value outside an enumerated set, a malformed email.
func UsageError(verb, format string, args ...any) *Error {
	return newError(KindUsage, verb, format, args...)
}

// AuthError reports an authentication or authorization failure.
func AuthError(verb, format string, args ...any) *Error {
	return newError(KindAuth, verb, format, args...)
}

// NotFoundError reports that the requested resource does not exist.
func NotFoundError(verb, format string, args ...any) *Error {
	return newError(KindNotFound, verb, format, args...)
}

// ConflictError reports a precondition or state-change conflict.
func ConflictError(verb, format string, args ...any) *Error {
	return newError(KindConflict, verb, format, args...)
}

// TransientError reports a failure that may succeed on retry.
func TransientError(verb, format string, args ...any) *Error {
	return newError(KindTransient, verb, format, args...)
}

// InternalError reports an unexpected condition inside Kura. Use
// sparingly — it tells the agent to escalate, not to retry.
func InternalError(verb, format string, args ...any) *Error {
	return newError(KindInternal, verb, format, args...)
}

// newError centralizes formatting and (when fmt.Errorf finds a %w in
// the format string) cause-wrapping for the typed constructors above.
func newError(kind Kind, verb, format string, args ...any) *Error {
	wrapped := fmt.Errorf(format, args...)
	return &Error{
		Kind:  kind,
		Verb:  verb,
		Msg:   wrapped.Error(),
		Cause: errors.Unwrap(wrapped),
	}
}

// ExitCode maps an error to the documented exit-code taxonomy. A nil
// error is 0 (success); a non-*Error error is 1 (unclassified
// failure) so an un-typed error never silently passes as success.
// errors.As walks wrapped chains, so a clio error wrapped with %w
// still resolves to its Kind.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var ce *Error
	if errors.As(err, &ce) {
		switch ce.Kind {
		case KindUsage:
			return 2
		case KindAuth:
			return 3
		case KindNotFound:
			return 4
		case KindConflict:
			return 5
		case KindTransient:
			return 6
		case KindInternal:
			return 7
		}
	}
	return 1
}
