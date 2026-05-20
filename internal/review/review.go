// Package review is the access-review subsystem: the durable record of a
// periodic attestation that the right people hold the right access. A
// Review is a point-in-time snapshot of the authorized list, the
// per-subject decision a reviewer made (approve or remove), and the
// completion metadata that turns a finished review into an archived,
// retrievable artifact.
//
// The store is enforcement-blind: it persists the attestation and nothing
// more. Remediation — actually revoking a flagged user's access — is the
// user store's job, orchestrated by the adapter; mixing it in here would
// make a second, divergent place that mutates access. Like the other
// stores, MemStore is the in-memory implementation for tests and
// database-less adapters; PostgresStore is the production tier over its
// own RLS-scoped table.
package review

import (
	"context"
	"errors"
	"time"
)

// ErrMissingDependency is returned by a store constructor when its wiring
// is incomplete.
var ErrMissingDependency = errors.New("review: missing required dependency")

// ErrNotFound is returned when no review exists for an id.
var ErrNotFound = errors.New("review: review not found")

// ErrClosed is returned when a mutation targets a review that is already
// completed — a completed review is an immutable artifact.
var ErrClosed = errors.New("review: review is completed and cannot be changed")

// ErrSubjectNotFound is returned when a decision targets an email that is
// not among the review's snapshot subjects.
var ErrSubjectNotFound = errors.New("review: subject not in this review")

// ErrEmptyReview is returned when a review is started with no subjects —
// there is nothing to attest.
var ErrEmptyReview = errors.New("review: a review needs at least one subject")

// Status is the lifecycle state of a review.
type Status string

const (
	// StatusOpen is a review still being worked: decisions can be recorded.
	StatusOpen Status = "open"
	// StatusCompleted is a finished, archived review: immutable.
	StatusCompleted Status = "completed"
)

// Decision is a reviewer's verdict on one subject.
type Decision string

const (
	// DecisionPending is the initial state of every subject: not yet
	// reviewed.
	DecisionPending Decision = "pending"
	// DecisionApproved attests the subject's access is correct.
	DecisionApproved Decision = "approved"
	// DecisionRemoved flags the subject's access for removal.
	DecisionRemoved Decision = "removed"
)

// recordable reports whether a decision is one a reviewer can record (not
// the initial pending state).
func (d Decision) recordable() bool {
	return d == DecisionApproved || d == DecisionRemoved
}

// Review is one periodic access review.
type Review struct {
	ID          string     `json:"id"`
	StartedAt   time.Time  `json:"started_at"`
	StartedBy   string     `json:"started_by"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Status      Status     `json:"status"`
	Items       []Item     `json:"items"`
}

// Item is one subject of a review: an authorized user, the roles they held
// when the review was started (the snapshot), and the reviewer's decision.
type Item struct {
	Email         string   `json:"email"`
	RolesAtReview []string `json:"roles_at_review"`
	Decision      Decision `json:"decision"`
	Note          string   `json:"note,omitempty"`
}

// Store persists access reviews. It is the seam the server's review
// endpoints sit on: an in-memory fake for tests, a Postgres-backed
// implementation for production.
type Store interface {
	// Create persists a new open review snapshotting subjects, attributed
	// to startedBy, and returns it with an assigned id, StartedAt, and
	// every item set to DecisionPending. ErrEmptyReview if subjects is
	// empty.
	Create(ctx context.Context, startedBy string, subjects []Item) (Review, error)
	// Get returns the review with id, or ErrNotFound.
	Get(ctx context.Context, id string) (Review, error)
	// List returns reviews newest-first.
	List(ctx context.Context) ([]Review, error)
	// Decide records decision (and an optional note) for email in an open
	// review. ErrNotFound, ErrClosed, ErrSubjectNotFound, or
	// ErrInvalidDecision as applicable.
	Decide(ctx context.Context, id, email string, decision Decision, note string) error
	// Complete marks an open review completed at the current time and
	// returns the archived artifact. ErrNotFound or ErrClosed.
	Complete(ctx context.Context, id string) (Review, error)
}

// ErrInvalidDecision is returned by Decide when the decision is not one a
// reviewer may record (only approved or removed).
var ErrInvalidDecision = errors.New("review: decision must be approved or removed")
