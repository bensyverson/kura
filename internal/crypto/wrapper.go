package crypto

import (
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Wrapper wraps and unwraps DEKs under the master KEK. The data layer and
// the DEK cache depend on this capability rather than on the raw KEK, so the
// key material's blast radius stays small: a caller can seal a fresh DEK and
// open a wrapped one without ever holding the KEK bytes. KeyWrapper is the
// production implementation; tests can substitute any Wrapper.
type Wrapper interface {
	Wrap(dek []byte) (wrapped []byte, err error)
	Unwrap(wrapped []byte) (dek []byte, err error)
}

// KeyWrapper implements Wrapper with a single in-memory master KEK, using
// the package's AES-256-GCM wrap primitives. It also satisfies
// keystore.Unwrapper, so the same value fronts both the write path (Wrap)
// and the DEK cache (Unwrap).
type KeyWrapper struct {
	kek []byte
}

// NewKeyWrapper returns a KeyWrapper over a 32-byte master KEK. A key of any
// other length is rejected: AES-256 is mandatory and a short KEK is a
// misconfiguration, not a weaker-cipher request.
func NewKeyWrapper(kek []byte) (*KeyWrapper, error) {
	if len(kek) != DEKSize {
		return nil, fmt.Errorf("%w: KEK is %d bytes", ErrInvalidKeySize, len(kek))
	}
	return &KeyWrapper{kek: slices.Clone(kek)}, nil
}

// NewKeyWrapperFromBase64 parses a base64-encoded 32-byte KEK and returns a
// KeyWrapper over it. This is the form the KEK takes in the secrets manager
// (FIELD_ENCRYPTION_KEY); see ParseKEK for the validation.
func NewKeyWrapperFromBase64(encoded string) (*KeyWrapper, error) {
	kek, err := ParseKEK(encoded)
	if err != nil {
		return nil, err
	}
	return NewKeyWrapper(kek)
}

// Wrap seals dek under the master KEK.
func (w *KeyWrapper) Wrap(dek []byte) ([]byte, error) {
	return WrapDEK(w.kek, dek)
}

// Unwrap recovers a DEK wrapped under the master KEK. A wrapped DEK from a
// different KEK fails authentication (ErrAuthentication).
func (w *KeyWrapper) Unwrap(wrapped []byte) ([]byte, error) {
	return UnwrapDEK(w.kek, wrapped)
}

// ParseKEK decodes a base64-encoded 32-byte master KEK as provisioned in the
// secrets manager. It fails loudly — empty, non-base64, or wrong length — so
// a misconfigured KEK is a clear startup error rather than a silent
// weakening of encryption. Generate one with `openssl rand -base64 32`.
func ParseKEK(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, errors.New("crypto: KEK is empty")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, fmt.Errorf("crypto: KEK is not valid base64: %w", err)
	}
	if len(raw) != DEKSize {
		return nil, fmt.Errorf("crypto: KEK must decode to %d bytes, got %d", DEKSize, len(raw))
	}
	return raw, nil
}
