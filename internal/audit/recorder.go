package audit

import (
	"context"
	"time"

	"github.com/bensyverson/kura/internal/identity"
)

// Recorder is the write side of the audit log. Every gate path —
// authentication, authorization, data access — funnels through one of
// its Record* methods, so emitting an audit event is not something a
// caller can forget: the methods take only structured metadata, and
// there is no parameter through which data contents could be passed.
type Recorder struct {
	store Store
	now   func() time.Time // injectable for tests
}

// NewRecorder returns a Recorder that writes to store.
func NewRecorder(store Store) *Recorder {
	return &Recorder{store: store, now: time.Now}
}

// RecordAuthentication logs that actor attempted to authenticate, with
// the given outcome.
func (r *Recorder) RecordAuthentication(ctx context.Context, actor identity.Principal, outcome Outcome) error {
	return r.store.Append(ctx, Event{
		Time:    r.now(),
		Kind:    KindAuthentication,
		Outcome: outcome,
		Actor:   actor,
		IP:      ClientIP(ctx),
	})
}

// RecordAuthorization logs an authorization decision: actor was allowed
// or denied the given action on the given resource.
func (r *Recorder) RecordAuthorization(ctx context.Context, actor identity.Principal, action string, resource Resource, outcome Outcome) error {
	return r.store.Append(ctx, Event{
		Time:     r.now(),
		Kind:     KindAuthorization,
		Outcome:  outcome,
		Actor:    actor,
		Action:   action,
		Resource: resource,
		IP:       ClientIP(ctx),
	})
}

// RecordAccess logs that actor accessed the given resource via the given
// action. A recorded access is one that occurred — a denied attempt is
// an authorization event, not an access event.
func (r *Recorder) RecordAccess(ctx context.Context, actor identity.Principal, action string, resource Resource) error {
	return r.store.Append(ctx, Event{
		Time:     r.now(),
		Kind:     KindAccess,
		Outcome:  OutcomeAllowed,
		Actor:    actor,
		Action:   action,
		Resource: resource,
		IP:       ClientIP(ctx),
	})
}
