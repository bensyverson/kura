package secrets

import (
	"context"
	"errors"
	"fmt"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/identity"
)

// EncryptionKeyName is the secret name under which the field-encryption
// key lives in the backend. The key is never a Go constant or a baked-in
// value: it is fetched through the backend like any other secret, so
// rotating it is an operational change in the secrets manager, not a
// code change or a redeploy.
const EncryptionKeyName = "FIELD_ENCRYPTION_KEY"

// EncryptionKeyRetiringName is the secret name under which the outgoing
// field-encryption KEK lives during a KEK rotation. It is loaded alongside
// EncryptionKeyName (the incoming/active key) only while a rotation is in
// flight — the operator declares the rotation via KURA_KEK_RETIRING_VERSION —
// so the read path can still open rows not yet re-wrapped under the new key.
// Outside a rotation it is unset and only the active key is loaded.
const EncryptionKeyRetiringName = "FIELD_ENCRYPTION_KEY_RETIRING"

// BackupEncryptionKeyName is the secret name for the key that encrypts
// logical backup dumps. It is deliberately distinct from
// EncryptionKeyName: the independent backup tier earns its
// compromise-resilience by using a key that is separate from the runtime
// field-encryption key, so a leak of one does not expose the other. Like
// every key it is fetched through the backend and rotatable there.
const BackupEncryptionKeyName = "BACKUP_ENCRYPTION_KEY"

// Errors returned by the secrets layer.
var (
	// ErrSecretNotFound is returned when a named secret is not present
	// in the backend.
	ErrSecretNotFound = errors.New("secrets: secret not found")
	// ErrEmptySecretName is returned when Get is called with no name.
	ErrEmptySecretName = errors.New("secrets: secret name is empty")
	// ErrMissingToken is returned when a Doppler backend is constructed
	// without a service token. The token is injected at runtime; an
	// empty one means the runtime injection did not happen.
	ErrMissingToken = errors.New("secrets: doppler service token is empty")
	// ErrMissingDopplerConfig is returned when a Doppler backend is
	// constructed without a project or config.
	ErrMissingDopplerConfig = errors.New("secrets: doppler project and config are required")
)

// Backend is the raw read interface over a secrets store: fetch a named
// secret value, nothing more. A concrete backend (DopplerBackend, or the
// test FakeBackend) implements only this. Authentication and auditing
// live one layer up in Manager, so no backend can forget them and the
// fake and the real implementation cannot drift on that contract.
type Backend interface {
	// Fetch returns the value of the named secret, or ErrSecretNotFound.
	Fetch(ctx context.Context, name string) (string, error)
}

// Manager is what the rest of Kura depends on to read secrets. It wraps
// a Backend with the two things every secret access requires: an
// authenticated actor and an audit event. There is no path through
// Manager that reads a secret without both — and no path that reads one
// from a baked-in env var or a committed file, because the only source
// is the injected Backend.
type Manager struct {
	backend  Backend
	recorder *audit.Recorder
}

// NewManager returns a Manager reading from backend and auditing through
// recorder.
func NewManager(backend Backend, recorder *audit.Recorder) *Manager {
	return &Manager{backend: backend, recorder: recorder}
}

// Get fetches the named secret on behalf of actor. The actor must be a
// valid, authenticated principal; the access is recorded as an audit
// event before the value is returned. If the access cannot be audited,
// Get fails closed: it returns an error and not the secret.
func (m *Manager) Get(ctx context.Context, actor identity.Principal, name string) (string, error) {
	if err := actor.Valid(); err != nil {
		return "", fmt.Errorf("secrets: secret access requires an authenticated principal: %w", err)
	}
	if name == "" {
		return "", ErrEmptySecretName
	}
	value, err := m.backend.Fetch(ctx, name)
	if err != nil {
		return "", err
	}
	// Audit before returning: an access Kura cannot record is an access
	// Kura does not grant. The recorded event names the actor and the
	// secret, never the value.
	if err := m.recorder.RecordAccess(ctx, actor, "secret.read", audit.Resource{
		Entity: "secret",
		ID:     name,
	}); err != nil {
		return "", fmt.Errorf("secrets: recording secret access: %w", err)
	}
	return value, nil
}

// EncryptionKey fetches the field-encryption key on behalf of actor. It
// is an ordinary audited Get against EncryptionKeyName — the key is
// managed in the backend and rotatable there.
func (m *Manager) EncryptionKey(ctx context.Context, actor identity.Principal) (string, error) {
	return m.Get(ctx, actor, EncryptionKeyName)
}
