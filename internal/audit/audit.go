// Package audit is Kura's append-only audit log: a structured record of
// every authentication, authorization decision, and data access.
//
// The cardinal rule: the audit log records that something happened and
// who did it — never what the data was. An Event holds only structured
// metadata (actor, action, resource identifier, time, outcome). It has
// no field — no byte slice, no map, no interface — that could carry
// opaque data contents, so there is structurally nowhere for client PII
// to land in the log. The audit log is itself sensitive, but at a
// different category than the data; it targets its own store with its
// own retention.
package audit

import (
	"time"

	"github.com/bensyverson/kura/internal/identity"
)

// Kind distinguishes the three sorts of event the audit log records.
// Authentication and authorization events are logged distinctly so an
// auditor can tell "who got in" from "what they were allowed to touch".
type Kind string

const (
	KindAuthentication Kind = "authentication"
	KindAuthorization  Kind = "authorization"
	KindAccess         Kind = "access"
)

// Outcome is the result of a decision: a request allowed, or denied.
type Outcome string

const (
	OutcomeAllowed Outcome = "allowed"
	OutcomeDenied  Outcome = "denied"
)

// Resource identifies what was acted on, by entity name and record id —
// identifiers only, never field values. The zero Resource is used for
// events that touch no specific record (e.g. authentication).
type Resource struct {
	Entity string
	ID     string
}

// Event is one append-only audit record. Every field is bounded,
// structured metadata; see the package doc for why that is the whole
// point.
type Event struct {
	Time     time.Time
	Kind     Kind
	Outcome  Outcome
	Actor    identity.Principal
	Action   string
	Resource Resource
	// IP is the real client IP the request came from, as recorded by the
	// adapter that served it (see WithClientIP). It is empty for events
	// recorded outside a request — a CLI-local call, for instance.
	IP string
}

// Filter selects events for a Query. A zero-valued field is "match any";
// an all-zero Filter matches every event. Since is inclusive and Until
// is exclusive, so adjacent time windows tile without overlap.
type Filter struct {
	Actor  string // matches Event.Actor.ID
	Entity string // matches Event.Resource.Entity
	Action string // matches Event.Action
	Since  time.Time
	Until  time.Time
}

// matches reports whether e satisfies the filter.
func (f Filter) matches(e Event) bool {
	if f.Actor != "" && e.Actor.ID != f.Actor {
		return false
	}
	if f.Entity != "" && e.Resource.Entity != f.Entity {
		return false
	}
	if f.Action != "" && e.Action != f.Action {
		return false
	}
	if !f.Since.IsZero() && e.Time.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && !e.Time.Before(f.Until) {
		return false
	}
	return true
}
