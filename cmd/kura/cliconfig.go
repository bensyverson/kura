package main

import (
	"fmt"
)

// serverInputs is the set of inputs resolveServer considers. The
// struct keeps the precedence rules legible and testable without
// reaching for global state.
type serverInputs struct {
	// flag is the literal --server value (empty when unset).
	flag string
	// client is the literal --client value (empty when unset).
	client string
	// profiles is the loaded profile set (never nil; an empty set is
	// represented as a profiles{} with no clients).
	profiles *profiles
	// cached is the server URL from the on-disk token cache (empty if
	// no cache, or the cache is for a different deployment).
	cached string
}

// resolveServer picks the remote server URL by precedence:
//  1. --server (explicit override)
//  2. --client (named profile lookup)
//  3. the cached credential's server (set by `kura login`)
//
// None of the three is an error — the agent gets a one-line message
// listing all three fixes. An unknown --client surfaces the profile
// layer's enumerating error untouched.
func resolveServer(in serverInputs) (string, error) {
	if in.flag != "" {
		return in.flag, nil
	}
	if in.client != "" {
		ep, err := in.profiles.endpoint(in.client)
		if err != nil {
			return "", err
		}
		return ep, nil
	}
	if in.cached != "" {
		return in.cached, nil
	}
	return "", fmt.Errorf("no remote server configured — pass --server <URL>, pass --client <name> (with a matching entry in ~/.config/kura/config.json), or run `kura login` to cache one")
}
