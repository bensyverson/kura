package secrets

import (
	"context"
	"errors"
	"testing"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/identity"
)

func testActor() identity.Principal {
	return identity.Principal{
		Type: identity.PrincipalService,
		ID:   "kura-api",
	}
}

func TestFakeBackendFetchReturnsSetValue(t *testing.T) {
	b := NewFakeBackend()
	b.Set("DB_PASSWORD", "hunter2")

	got, err := b.Fetch(context.Background(), "DB_PASSWORD")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got != "hunter2" {
		t.Errorf("Fetch = %q, want %q", got, "hunter2")
	}
}

func TestFakeBackendFetchMissingReturnsErrSecretNotFound(t *testing.T) {
	b := NewFakeBackend()
	if _, err := b.Fetch(context.Background(), "ABSENT"); !errors.Is(err, ErrSecretNotFound) {
		t.Errorf("Fetch missing err = %v, want ErrSecretNotFound", err)
	}
}

func TestManagerGetReturnsSecretValue(t *testing.T) {
	b := NewFakeBackend()
	b.Set("DB_PASSWORD", "hunter2")
	m := NewManager(b, audit.NewRecorder(audit.NewMemStore()))

	got, err := m.Get(context.Background(), testActor(), "DB_PASSWORD")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "hunter2" {
		t.Errorf("Get = %q, want %q", got, "hunter2")
	}
}

func TestManagerGetEmitsAuditAccessEvent(t *testing.T) {
	b := NewFakeBackend()
	b.Set("DB_PASSWORD", "hunter2")
	store := audit.NewMemStore()
	m := NewManager(b, audit.NewRecorder(store))

	if _, err := m.Get(context.Background(), testActor(), "DB_PASSWORD"); err != nil {
		t.Fatalf("Get: %v", err)
	}

	events, err := store.Query(context.Background(), audit.Filter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("recorded %d events, want 1", len(events))
	}
	e := events[0]
	if e.Kind != audit.KindAccess {
		t.Errorf("event Kind = %q, want %q", e.Kind, audit.KindAccess)
	}
	if e.Actor.ID != "kura-api" {
		t.Errorf("event Actor.ID = %q, want %q", e.Actor.ID, "kura-api")
	}
	if e.Resource.Entity != "secret" || e.Resource.ID != "DB_PASSWORD" {
		t.Errorf("event Resource = %+v, want {secret DB_PASSWORD}", e.Resource)
	}
	// The audit event must never carry the secret value itself — the
	// Event type has no field for it, so this is structural, but assert
	// the action is the read verb and nothing leaked into Action.
	if e.Action != "secret.read" {
		t.Errorf("event Action = %q, want %q", e.Action, "secret.read")
	}
}

func TestManagerGetRejectsInvalidActor(t *testing.T) {
	b := NewFakeBackend()
	b.Set("DB_PASSWORD", "hunter2")
	store := audit.NewMemStore()
	m := NewManager(b, audit.NewRecorder(store))

	// A zero principal is not authenticated.
	_, err := m.Get(context.Background(), identity.Principal{}, "DB_PASSWORD")
	if err == nil {
		t.Fatal("Get with invalid actor: want error, got nil")
	}

	events, _ := store.Query(context.Background(), audit.Filter{})
	if len(events) != 0 {
		t.Errorf("rejected access recorded %d events, want 0", len(events))
	}
}

func TestManagerGetRejectsEmptyName(t *testing.T) {
	m := NewManager(NewFakeBackend(), audit.NewRecorder(audit.NewMemStore()))
	if _, err := m.Get(context.Background(), testActor(), ""); !errors.Is(err, ErrEmptySecretName) {
		t.Errorf("Get empty name err = %v, want ErrEmptySecretName", err)
	}
}

func TestManagerGetMissingSecretIsNotRecordedAsAccess(t *testing.T) {
	store := audit.NewMemStore()
	m := NewManager(NewFakeBackend(), audit.NewRecorder(store))

	_, err := m.Get(context.Background(), testActor(), "ABSENT")
	if !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("Get missing err = %v, want ErrSecretNotFound", err)
	}
	events, _ := store.Query(context.Background(), audit.Filter{})
	if len(events) != 0 {
		t.Errorf("failed fetch recorded %d events, want 0 — nothing was accessed", len(events))
	}
}

// failingStore is an audit.Store whose Append always errors, used to
// prove Manager fails closed: an access it cannot audit must not succeed.
type failingStore struct{}

func (failingStore) Append(context.Context, audit.Event) error {
	return errors.New("audit store down")
}
func (failingStore) Query(context.Context, audit.Filter) ([]audit.Event, error) {
	return nil, nil
}
func (failingStore) Subscribe(context.Context) <-chan audit.Event {
	ch := make(chan audit.Event)
	close(ch)
	return ch
}

func TestManagerGetFailsClosedWhenAuditFails(t *testing.T) {
	b := NewFakeBackend()
	b.Set("DB_PASSWORD", "hunter2")
	m := NewManager(b, audit.NewRecorder(failingStore{}))

	got, err := m.Get(context.Background(), testActor(), "DB_PASSWORD")
	if err == nil {
		t.Fatal("Get with failing audit: want error, got nil")
	}
	if got != "" {
		t.Errorf("Get with failing audit returned secret %q, want empty — must fail closed", got)
	}
}

func TestEncryptionKeyIsFetchedFromBackendAndRotatable(t *testing.T) {
	b := NewFakeBackend()
	store := audit.NewMemStore()
	m := NewManager(b, audit.NewRecorder(store))

	// The key is not hardcoded: it comes from the backend.
	b.Set(EncryptionKeyName, "key-v1")
	got, err := m.EncryptionKey(context.Background(), testActor())
	if err != nil {
		t.Fatalf("EncryptionKey: %v", err)
	}
	if got != "key-v1" {
		t.Errorf("EncryptionKey = %q, want %q", got, "key-v1")
	}

	// It is rotatable: rotating the value in the backend rotates the key
	// Kura uses, with no code change.
	b.Set(EncryptionKeyName, "key-v2")
	got, err = m.EncryptionKey(context.Background(), testActor())
	if err != nil {
		t.Fatalf("EncryptionKey after rotation: %v", err)
	}
	if got != "key-v2" {
		t.Errorf("EncryptionKey after rotation = %q, want %q", got, "key-v2")
	}

	// Fetching the encryption key is itself audited.
	events, _ := store.Query(context.Background(), audit.Filter{})
	if len(events) != 2 {
		t.Errorf("encryption key access recorded %d events, want 2", len(events))
	}
}

var _ Backend = (*FakeBackend)(nil)
var _ Backend = (*DopplerBackend)(nil)
