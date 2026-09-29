package crypto

import (
	"errors"
	"fmt"
	"maps"
)

// ErrUnknownKEKVersion is returned when a KeyRing is asked to unwrap under a
// KEK generation it does not hold. It is deliberately distinct from
// ErrAuthentication: a missing key is an operator misconfiguration (e.g. the
// retiring KEK was not loaded during a rotation), whereas an authentication
// failure means the wrapped bytes were tampered with. Collapsing the two
// would let a config mistake masquerade as an integrity violation.
var ErrUnknownKEKVersion = errors.New("crypto: no KEK for version")

// KeyRing holds the master KEKs by generation, with one marked active. It is
// what makes an online, batched KEK rotation safe: while a rotation is in
// flight the key store holds a mix of generations, so the write path seals
// under the active KEK (stamping the row with that generation) and the read
// path opens each row under whichever generation wrapped it. Outside a
// rotation the ring holds a single generation and behaves like one KEK.
type KeyRing struct {
	wrappers map[int]Wrapper
	active   int
}

// NewKeyRing returns a ring over wrappers keyed by generation, with active
// marked as the generation new writes seal under. active must be present in
// the set — otherwise the write path would stamp a version it cannot itself
// open — and the set must be non-empty.
func NewKeyRing(active int, wrappers map[int]Wrapper) (*KeyRing, error) {
	if len(wrappers) == 0 {
		return nil, errors.New("crypto: key ring needs at least one KEK")
	}
	if _, ok := wrappers[active]; !ok {
		return nil, fmt.Errorf("crypto: active KEK version %d is not in the key ring", active)
	}
	return &KeyRing{wrappers: maps.Clone(wrappers), active: active}, nil
}

// WrapActive seals dek under the active generation's KEK and returns the
// wrapped bytes together with that generation, so the caller can persist the
// row's kek_version to match the key that wrapped it.
func (r *KeyRing) WrapActive(dek []byte) (wrapped []byte, version int, err error) {
	wrapped, err = r.wrappers[r.active].Wrap(dek)
	if err != nil {
		return nil, 0, err
	}
	return wrapped, r.active, nil
}

// Unwrap recovers a DEK wrapped under the named generation's KEK. A version
// the ring does not hold is ErrUnknownKEKVersion; wrapped bytes that fail to
// authenticate under the correct key are ErrAuthentication.
func (r *KeyRing) Unwrap(wrapped []byte, version int) (dek []byte, err error) {
	w, ok := r.wrappers[version]
	if !ok {
		return nil, fmt.Errorf("%w: %d", ErrUnknownKEKVersion, version)
	}
	return w.Unwrap(wrapped)
}

// ActiveVersion reports the generation new writes seal under.
func (r *KeyRing) ActiveVersion() int {
	return r.active
}
