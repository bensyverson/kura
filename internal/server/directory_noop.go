package server

import (
	"context"

	"github.com/bensyverson/kura/internal/identity"
)

// noopDirectory is the Directory implementation for IdPs that expose
// no standard directory API — generic OIDC chiefly. It always reports
// AccountActive: the mismatch endpoint then surfaces no mismatches,
// which is the truth (Kura cannot ask) and never produces a false
// positive that would mislead an admin.
//
// Deployments using noopDirectory must compensate at the IdP side:
// shorter token lifetimes, IdP-side session revocation, and timely
// removal from the Kura authorized-user list when a person leaves.
type noopDirectory struct{}

var _ identity.Directory = (*noopDirectory)(nil)

// NewNoopDirectory returns the noop directory for the generic-OIDC
// path. Exported so the kura serve adapter can wire it from
// KURA_IDP=oidc; the type itself is intentionally unexported.
func NewNoopDirectory() identity.Directory { return &noopDirectory{} }

// AccountStatus returns AccountActive for every email; the noop
// directory has nothing else to say.
func (noopDirectory) AccountStatus(_ context.Context, _ string) (identity.AccountStatus, error) {
	return identity.AccountActive, nil
}
