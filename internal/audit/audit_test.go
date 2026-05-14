package audit

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/bensyverson/kura/internal/identity"
)

func testActor() identity.Principal {
	return identity.Principal{
		Type:   identity.PrincipalUser,
		ID:     "alice@client.com",
		Email:  "alice@client.com",
		Domain: "client.com",
	}
}

// ZDA: an audit Event must hold only structured metadata. The type
// itself must offer no field — no []byte, no map, no interface{} — that
// could hold opaque data contents. This is the structural guarantee that
// no caller (and no test) can ever put data contents into an audit
// record.
func TestEventStructHasNoOpaqueFields(t *testing.T) {
	et := reflect.TypeFor[Event]()
	for f := range et.Fields() {
		switch f.Type.Kind() {
		case reflect.String, reflect.Struct, reflect.Bool,
			reflect.Int, reflect.Int64:
			// bounded, structured metadata — fine
		default:
			t.Errorf("Event.%s is %s — audit events must hold only structured "+
				"metadata, never a slot for opaque data contents", f.Name, f.Type.Kind())
		}
	}
}

// The real client IP of a request is request-scoped metadata: an adapter
// stashes it on the context, and every event the recorder writes while
// serving that request carries it. An event recorded without an IP on
// the context (a CLI-local call, say) simply has an empty IP.
func TestRecorderRecordsClientIPFromContext(t *testing.T) {
	store := NewMemStore()
	rec := NewRecorder(store)
	actor := testActor()
	res := Resource{Entity: "customer", ID: "cust-1"}

	ctx := WithClientIP(context.Background(), "203.0.113.7")
	if err := rec.RecordAuthentication(ctx, actor, OutcomeAllowed); err != nil {
		t.Fatalf("RecordAuthentication: %v", err)
	}
	if err := rec.RecordAuthorization(ctx, actor, "read", res, OutcomeAllowed); err != nil {
		t.Fatalf("RecordAuthorization: %v", err)
	}
	if err := rec.RecordAccess(ctx, actor, "read", res); err != nil {
		t.Fatalf("RecordAccess: %v", err)
	}
	// A call with no IP on the context records an empty IP, not a panic.
	if err := rec.RecordAccess(context.Background(), actor, "read", res); err != nil {
		t.Fatalf("RecordAccess (no IP): %v", err)
	}

	events, err := store.Query(context.Background(), Filter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(events) != 4 {
		t.Fatalf("expected 4 events, got %d", len(events))
	}
	for _, e := range events[:3] {
		if e.IP != "203.0.113.7" {
			t.Errorf("%s event IP = %q, want %q", e.Kind, e.IP, "203.0.113.7")
		}
	}
	if events[3].IP != "" {
		t.Errorf("event recorded without an IP on the context has IP = %q, want empty", events[3].IP)
	}
}

// cBg: each decision kind emits a well-formed, structured event.
func TestRecorderEmitsStructuredEvents(t *testing.T) {
	store := NewMemStore()
	rec := NewRecorder(store)
	ctx := context.Background()
	actor := testActor()
	res := Resource{Entity: "customer", ID: "cust-1"}

	if err := rec.RecordAuthentication(ctx, actor, OutcomeAllowed); err != nil {
		t.Fatalf("RecordAuthentication: %v", err)
	}
	if err := rec.RecordAuthorization(ctx, actor, "read", res, OutcomeDenied); err != nil {
		t.Fatalf("RecordAuthorization: %v", err)
	}
	if err := rec.RecordAccess(ctx, actor, "read", res); err != nil {
		t.Fatalf("RecordAccess: %v", err)
	}

	events, err := store.Query(ctx, Filter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}
	for _, e := range events {
		if e.Actor != actor {
			t.Errorf("event actor = %+v, want %+v", e.Actor, actor)
		}
		if e.Time.IsZero() {
			t.Error("event has no timestamp")
		}
	}
}

// The description requires authentication and authorization events to be
// logged distinctly.
func TestAuthnAndAuthzLoggedDistinctly(t *testing.T) {
	store := NewMemStore()
	rec := NewRecorder(store)
	ctx := context.Background()
	actor := testActor()

	_ = rec.RecordAuthentication(ctx, actor, OutcomeAllowed)
	_ = rec.RecordAuthorization(ctx, actor, "read", Resource{Entity: "customer", ID: "c1"}, OutcomeAllowed)
	_ = rec.RecordAccess(ctx, actor, "read", Resource{Entity: "customer", ID: "c1"})

	events, _ := store.Query(ctx, Filter{})
	kinds := map[Kind]int{}
	for _, e := range events {
		kinds[e.Kind]++
	}
	for _, k := range []Kind{KindAuthentication, KindAuthorization, KindAccess} {
		if kinds[k] != 1 {
			t.Errorf("expected exactly 1 %q event, got %d", k, kinds[k])
		}
	}
}

func TestQueryByActorResourceAction(t *testing.T) {
	store := NewMemStore()
	ctx := context.Background()
	alice := identity.Principal{Type: identity.PrincipalUser, ID: "alice@c.com", Email: "alice@c.com", Domain: "c.com"}
	bob := identity.Principal{Type: identity.PrincipalAdmin, ID: "bob@c.com", Email: "bob@c.com", Domain: "c.com"}

	base := time.Date(2026, 5, 14, 9, 0, 0, 0, time.UTC)
	must := func(e Event) {
		if err := store.Append(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	must(Event{Time: base, Kind: KindAccess, Outcome: OutcomeAllowed, Actor: alice, Action: "read", Resource: Resource{Entity: "customer", ID: "c1"}})
	must(Event{Time: base, Kind: KindAccess, Outcome: OutcomeAllowed, Actor: bob, Action: "read", Resource: Resource{Entity: "customer", ID: "c2"}})
	must(Event{Time: base, Kind: KindAccess, Outcome: OutcomeAllowed, Actor: alice, Action: "list", Resource: Resource{Entity: "order", ID: ""}})

	if got, _ := store.Query(ctx, Filter{Actor: "alice@c.com"}); len(got) != 2 {
		t.Errorf("by actor: expected 2 events, got %d", len(got))
	}
	if got, _ := store.Query(ctx, Filter{Entity: "customer"}); len(got) != 2 {
		t.Errorf("by resource entity: expected 2 events, got %d", len(got))
	}
	if got, _ := store.Query(ctx, Filter{Action: "list"}); len(got) != 1 {
		t.Errorf("by action: expected 1 event, got %d", len(got))
	}
	if got, _ := store.Query(ctx, Filter{Actor: "alice@c.com", Action: "read"}); len(got) != 1 {
		t.Errorf("by actor+action: expected 1 event, got %d", len(got))
	}
}

func TestQueryByTimeRange(t *testing.T) {
	store := NewMemStore()
	ctx := context.Background()
	actor := testActor()
	base := time.Date(2026, 5, 14, 9, 0, 0, 0, time.UTC)
	for i := range 3 {
		_ = store.Append(ctx, Event{
			Time: base.Add(time.Duration(i) * time.Hour), Kind: KindAccess,
			Outcome: OutcomeAllowed, Actor: actor, Action: "read",
			Resource: Resource{Entity: "customer", ID: "c1"},
		})
	}

	// Since is inclusive: drops the 09:00 event.
	if got, _ := store.Query(ctx, Filter{Since: base.Add(time.Hour)}); len(got) != 2 {
		t.Errorf("Since filter: expected 2 events, got %d", len(got))
	}
	// Until is exclusive: drops the 11:00 event.
	if got, _ := store.Query(ctx, Filter{Until: base.Add(2 * time.Hour)}); len(got) != 2 {
		t.Errorf("Until filter: expected 2 events, got %d", len(got))
	}
	// Both: only the 10:00 event.
	if got, _ := store.Query(ctx, Filter{Since: base.Add(time.Hour), Until: base.Add(2 * time.Hour)}); len(got) != 1 {
		t.Errorf("Since+Until filter: expected 1 event, got %d", len(got))
	}
}

func TestSubscribeReceivesNewEvents(t *testing.T) {
	store := NewMemStore()
	ctx := t.Context()

	ch := store.Subscribe(ctx)
	rec := NewRecorder(store)
	if err := rec.RecordAccess(ctx, testActor(), "read", Resource{Entity: "customer", ID: "c1"}); err != nil {
		t.Fatalf("RecordAccess: %v", err)
	}

	select {
	case e := <-ch:
		if e.Kind != KindAccess || e.Actor.ID != "alice@client.com" {
			t.Errorf("subscriber got unexpected event: %+v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber did not receive the appended event")
	}
}
