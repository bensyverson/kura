// Package secrets is Kura's secrets-manager abstraction: the single path
// through which every secret — database passwords, OAuth client secrets,
// the field-encryption key, API keys — reaches the rest of the system.
//
// The layering is deliberate:
//
//   - Backend is the raw read interface — Fetch a named secret, nothing
//     more. DopplerBackend is the production implementation (Doppler is
//     the Standard-Regulated backend; see
//     docs/content/docs/concepts/secrets.md); FakeBackend is the
//     in-memory test double. Neither reads from a baked-in env var or a
//     committed file: DopplerBackend takes its service token as a
//     constructor argument, injected at runtime by the deployment, and
//     FakeBackend holds only what a test sets.
//
//   - Manager is what the rest of Kura depends on. It wraps a Backend
//     with the two things every secret access requires — an
//     authenticated principal and an audit event — so neither can be
//     forgotten and the fake and the real backend cannot drift on that
//     contract. A secret access Kura cannot audit is one it does not
//     grant: Manager.Get fails closed.
//
// The field-encryption key is an ordinary secret, fetched by name
// (EncryptionKeyName) through the audited path. It is managed in the
// backend and rotatable there — never a Go constant, never hardcoded.
package secrets
