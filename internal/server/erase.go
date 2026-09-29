package server

import (
	"context"
	"errors"
	"net/http"

	"github.com/bensyverson/kura/internal/data"
	"github.com/bensyverson/kura/internal/gate"
	"github.com/bensyverson/kura/internal/identity"
)

// registerEraseRoute mounts the crypto-shred erasure endpoint. It is a
// gatedEraseHandler, so every erasure runs through Gate.Erase — authorized
// against the caller's roles (admin only) and audited, by construction.
// Erasure is domain-agnostic: it names records by id, never an entity, so
// it is a single top-level route rather than one per entity.
func (s *Server) registerEraseRoute() {
	s.registerErase("POST /api/erase", eraseBindingFor(s.cfg.Eraser))
}

// eraseRequestBody is the body of POST /api/erase: the ids of the records
// whose per-value keys are to be shredded.
type eraseRequestBody struct {
	RecordIDs []string `json:"record_ids"`
}

// eraseBindingFor builds the binding for POST /api/erase: shred the DEKs
// for the named records. A destructive operation, so it needs the admin
// role. The tenant is the authenticated principal's, resolved by the gate
// from the token — never taken from the request body.
func eraseBindingFor(eraser data.Eraser) eraseBinding {
	return func(r *http.Request, _ identity.Principal) (gate.EraseRequest, gate.Eraser, error) {
		var body eraseRequestBody
		if err := decodeJSON(r, &body); err != nil {
			return gate.EraseRequest{}, nil, err
		}
		if len(body.RecordIDs) == 0 {
			return gate.EraseRequest{}, nil, errors.New("server: erase requires at least one record id")
		}
		req := gate.EraseRequest{
			Token:     bearerToken(r),
			RecordIDs: body.RecordIDs,
		}
		shred := func(ctx context.Context, ids []string) (int, error) {
			return eraser.Erase(ctx, ids)
		}
		return req, shred, nil
	}
}
