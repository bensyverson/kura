package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/bensyverson/kura/internal/crypto"
	"github.com/bensyverson/kura/internal/secrets"
)

// Environment variables that configure the KEK generations. Version numbers
// are non-sensitive configuration read from the environment; only the key
// material is sourced from the secrets backend.
const (
	kekVersionVar         = "KURA_KEK_VERSION"
	kekRetiringVersionVar = "KURA_KEK_RETIRING_VERSION"
)

// buildKeyRing sources the KEK generations from the secrets backend into a
// crypto.KeyRing. The active generation (kekVersionVar, default 1) is the key
// new writes seal under, fetched under secrets.EncryptionKeyName. During a
// rotation the operator declares kekRetiringVersionVar, and the outgoing key
// is fetched under secrets.EncryptionKeyRetiringName and loaded alongside the
// active one, so the read path can still open rows not yet re-wrapped. Version
// numbers come from getenv (non-sensitive config); key material comes only
// from the backend. A missing or malformed key is a fail-fast startup error.
func buildKeyRing(ctx context.Context, backend secrets.Backend, getenv func(string) string) (*crypto.KeyRing, error) {
	activeVersion, err := kekVersionEnv(getenv, kekVersionVar, 1)
	if err != nil {
		return nil, err
	}
	activeWrapper, err := fetchWrapper(ctx, backend, secrets.EncryptionKeyName)
	if err != nil {
		return nil, err
	}
	wrappers := map[int]crypto.Wrapper{activeVersion: activeWrapper}

	if raw := getenv(kekRetiringVersionVar); strings.TrimSpace(raw) != "" {
		retiringVersion, err := parsePositiveInt(raw, kekRetiringVersionVar)
		if err != nil {
			return nil, err
		}
		if retiringVersion >= activeVersion {
			return nil, fmt.Errorf("serve: %s (%d) must be below the active %s (%d)", kekRetiringVersionVar, retiringVersion, kekVersionVar, activeVersion)
		}
		retiringWrapper, err := fetchWrapper(ctx, backend, secrets.EncryptionKeyRetiringName)
		if err != nil {
			return nil, err
		}
		wrappers[retiringVersion] = retiringWrapper
	}

	ring, err := crypto.NewKeyRing(activeVersion, wrappers)
	if err != nil {
		return nil, fmt.Errorf("serve: building key ring: %w", err)
	}
	return ring, nil
}

// fetchWrapper sources the base64 KEK named `name` from the backend and turns
// it into a wrap/unwrap capability, keeping the raw key's blast radius small.
func fetchWrapper(ctx context.Context, backend secrets.Backend, name string) (*crypto.KeyWrapper, error) {
	encoded, err := backend.Fetch(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("serve: sourcing %s from the secrets manager: %w", name, err)
	}
	w, err := crypto.NewKeyWrapperFromBase64(encoded)
	if err != nil {
		return nil, fmt.Errorf("serve: %s: %w", name, err)
	}
	return w, nil
}

// kekVersionEnv reads a positive-integer KEK generation from getenv, returning
// def when the variable is unset.
func kekVersionEnv(getenv func(string) string, key string, def int) (int, error) {
	raw := getenv(key)
	if strings.TrimSpace(raw) == "" {
		return def, nil
	}
	return parsePositiveInt(raw, key)
}

// parsePositiveInt parses raw as an integer >= 1, attributing any failure to
// the named variable so a misconfiguration is a clear startup error.
func parsePositiveInt(raw, key string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("serve: %s must be an integer, got %q", key, raw)
	}
	if n < 1 {
		return 0, fmt.Errorf("serve: %s must be >= 1, got %d", key, n)
	}
	return n, nil
}
