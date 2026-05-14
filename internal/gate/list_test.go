package gate

import (
	"context"
	"errors"
	"testing"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/cedar"
)

// patientListFetcher returns n patient records, all carrying the same
// PII the harness's detector is primed to find. It also records the
// limit and offset the gate passed it, so a test can assert the gate
// clamped the page size before the fetch ran.
func patientListFetcher(n int, gotLimit, gotOffset *int) ListFetcher {
	return func(_ context.Context, limit, offset int) ([]Record, error) {
		if gotLimit != nil {
			*gotLimit = limit
		}
		if gotOffset != nil {
			*gotOffset = offset
		}
		recs := make([]Record, n)
		for i := range recs {
			recs[i] = Record{
				ID: string(rune('a' + i)),
				Fields: map[string]string{
					"full_name": "Jane Doe",
					"email":     "jane@example.com",
					"account":   "ACCT-555",
				},
			}
		}
		return recs, nil
	}
}

func TestListRunsTheFullChainForAnAuthorizedAdmin(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "alice", "admin")

	res, err := h.gate.List(context.Background(), ListRequest{
		Token: tok, Entity: "patient", Limit: 10,
	}, patientListFetcher(3, nil, nil))
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if res.Principal.ID != "alice" {
		t.Errorf("result Principal.ID = %q, want alice", res.Principal.ID)
	}
	if len(res.Records) != 3 {
		t.Fatalf("got %d records, want 3", len(res.Records))
	}
	for _, r := range res.Records {
		if r.Fields["account"] != "ACCT-555" {
			t.Errorf("admin account = %q, want plaintext", r.Fields["account"])
		}
	}
	kinds := eventKinds(t, h.store)
	want := []audit.Kind{audit.KindAuthentication, audit.KindAuthorization, audit.KindAccess}
	if len(kinds) != 3 || kinds[0] != want[0] || kinds[1] != want[1] || kinds[2] != want[2] {
		t.Errorf("audit kinds = %v, want %v", kinds, want)
	}
}

// Masking in a list is per-record and identical to a single Access: a
// user sees high-sensitivity categories redacted in every record.
func TestListMasksHighSensitivityForAUser(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "bob", "user")

	res, err := h.gate.List(context.Background(), ListRequest{
		Token: tok, Entity: "patient", Limit: 10,
	}, patientListFetcher(2, nil, nil))
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, r := range res.Records {
		if r.Fields["full_name"] != "Jane Doe" {
			t.Errorf("user full_name = %q, want plaintext", r.Fields["full_name"])
		}
		if r.Fields["account"] != Redacted {
			t.Errorf("user account = %q, want %q", r.Fields["account"], Redacted)
		}
	}
}

// A list request with no limit gets the documented default page size,
// and that is the limit the gate hands the fetcher.
func TestListAppliesDefaultPageSizeWhenUnset(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "alice", "admin")

	var gotLimit int
	res, err := h.gate.List(context.Background(), ListRequest{
		Token: tok, Entity: "patient", Limit: 0,
	}, patientListFetcher(1, &gotLimit, nil))
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if gotLimit != DefaultPageSize {
		t.Errorf("fetcher got limit %d, want the default %d", gotLimit, DefaultPageSize)
	}
	if res.Limit != DefaultPageSize {
		t.Errorf("result Limit = %d, want the default %d", res.Limit, DefaultPageSize)
	}
}

// A list request asking for more than the ceiling is clamped: the gate
// is "bounded by default", so an adapter cannot dump an unbounded set.
func TestListClampsPageSizeToTheMax(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "alice", "admin")

	var gotLimit, gotOffset int
	res, err := h.gate.List(context.Background(), ListRequest{
		Token: tok, Entity: "patient", Limit: MaxPageSize + 5000, Offset: 40,
	}, patientListFetcher(1, &gotLimit, &gotOffset))
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if gotLimit != MaxPageSize {
		t.Errorf("fetcher got limit %d, want the ceiling %d", gotLimit, MaxPageSize)
	}
	if res.Limit != MaxPageSize {
		t.Errorf("result Limit = %d, want the ceiling %d", res.Limit, MaxPageSize)
	}
	if gotOffset != 40 || res.Offset != 40 {
		t.Errorf("offset = %d/%d, want 40 passed through unchanged", gotOffset, res.Offset)
	}
}

// One list call is one audit Access event, regardless of how many
// records the page held — the event records that the list happened, on
// the entity, with no specific record id.
func TestListAuditsOnceForThePage(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "alice", "admin")

	if _, err := h.gate.List(context.Background(), ListRequest{
		Token: tok, Entity: "patient", Limit: 10,
	}, patientListFetcher(25, nil, nil)); err != nil {
		t.Fatalf("List: %v", err)
	}
	events, err := h.store.Query(context.Background(), audit.Filter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	var access []audit.Event
	for _, e := range events {
		if e.Kind == audit.KindAccess {
			access = append(access, e)
		}
	}
	if len(access) != 1 {
		t.Fatalf("got %d access events for one list of 25, want exactly 1", len(access))
	}
	if access[0].Action != string(cedar.ActionList) {
		t.Errorf("access event action = %q, want %q", access[0].Action, cedar.ActionList)
	}
	if access[0].Resource.Entity != "patient" || access[0].Resource.ID != "" {
		t.Errorf("access event resource = %+v, want patient with empty id", access[0].Resource)
	}
}

// A principal with no roles is denied: List returns ErrDenied, never
// runs the fetcher, and records the denial as an authorization event.
func TestListDeniedForUnauthorizedPrincipal(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "mallory") // no roles assigned

	fetched := false
	fetch := func(_ context.Context, _, _ int) ([]Record, error) {
		fetched = true
		return nil, nil
	}
	_, err := h.gate.List(context.Background(), ListRequest{
		Token: tok, Entity: "patient", Limit: 10,
	}, fetch)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("List denied err = %v, want ErrDenied", err)
	}
	if fetched {
		t.Error("fetcher ran for a denied list request")
	}
	kinds := eventKinds(t, h.store)
	want := []audit.Kind{audit.KindAuthentication, audit.KindAuthorization}
	if len(kinds) != 2 || kinds[0] != want[0] || kinds[1] != want[1] {
		t.Errorf("audit kinds = %v, want %v", kinds, want)
	}
}

func TestListUnknownEntityReturnsError(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "alice", "admin")

	_, err := h.gate.List(context.Background(), ListRequest{
		Token: tok, Entity: "ghost", Limit: 10,
	}, patientListFetcher(1, nil, nil))
	if !errors.Is(err, ErrUnknownEntity) {
		t.Errorf("List unknown entity err = %v, want ErrUnknownEntity", err)
	}
}

func TestListPropagatesFetchError(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "alice", "admin")
	fetch := func(_ context.Context, _, _ int) ([]Record, error) {
		return nil, errors.New("database unreachable")
	}

	_, err := h.gate.List(context.Background(), ListRequest{
		Token: tok, Entity: "patient", Limit: 10,
	}, fetch)
	if err == nil {
		t.Fatal("List with failing fetch: want error, got nil")
	}
	for _, k := range eventKinds(t, h.store) {
		if k == audit.KindAccess {
			t.Error("an access event was recorded although the fetch failed")
		}
	}
}

// A negative offset is meaningless; the gate floors it at zero rather
// than handing a negative offset to the fetcher.
func TestListFloorsNegativeOffset(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "alice", "admin")

	var gotOffset int
	if _, err := h.gate.List(context.Background(), ListRequest{
		Token: tok, Entity: "patient", Limit: 10, Offset: -5,
	}, patientListFetcher(1, nil, &gotOffset)); err != nil {
		t.Fatalf("List: %v", err)
	}
	if gotOffset != 0 {
		t.Errorf("fetcher got offset %d, want 0 (negative floored)", gotOffset)
	}
}
