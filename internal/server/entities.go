package server

import (
	"context"
	"net/http"
	"strconv"

	"github.com/bensyverson/kura/internal/cedar"
	"github.com/bensyverson/kura/internal/data"
	"github.com/bensyverson/kura/internal/gate"
	"github.com/bensyverson/kura/internal/identity"
)

// registerEntityRoutes generates the data-route pair — a get and a list —
// for every entity the gate's manifest declares. The routing tree is a
// function of the manifest, not a hand-maintained list: a client adds an
// entity to its manifest and the API grows the matching routes with no
// per-entity code. With an empty manifest no routes are generated, which
// is exactly right for a server that has no schema yet.
func (s *Server) registerEntityRoutes() {
	for _, e := range s.cfg.Gate.Manifest().Entities {
		entity := e.Name
		s.registerData("GET /api/"+entity+"/{id}", getBinding(entity, s.cfg.Records))
		s.registerListData("GET /api/"+entity, listBindingFor(entity, s.cfg.Records))
	}
}

// getBinding builds the binding for an entity's single-record route: it
// names the gate AccessRequest and supplies a Fetcher that reads the
// record from the store. A record the store does not have surfaces as
// data.ErrNotFound, which the gated handler maps to a 404 — a not-found,
// not a server error.
func getBinding(entity string, store data.RecordStore) dataBinding {
	return func(r *http.Request, _ identity.Principal) (gate.AccessRequest, gate.Fetcher, error) {
		id := r.PathValue("id")
		req := gate.AccessRequest{
			Token:      bearerToken(r),
			Action:     cedar.ActionRead,
			Entity:     entity,
			ResourceID: id,
		}
		fetch := func(ctx context.Context) (map[string]string, error) {
			rec, ok, err := store.Get(ctx, entity, id)
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, data.ErrNotFound
			}
			return rec.Fields, nil
		}
		return req, fetch, nil
	}
}

// listBindingFor builds the binding for an entity's list route: it parses
// the pagination query parameters into a gate ListRequest and supplies a
// ListFetcher that reads the page from the store. The gate clamps the
// page bounds before the fetch runs; the store just reads what it is
// asked for.
func listBindingFor(entity string, store data.RecordStore) listBinding {
	return func(r *http.Request, _ identity.Principal) (gate.ListRequest, gate.ListFetcher, error) {
		limit, offset, err := parsePageParams(r)
		if err != nil {
			return gate.ListRequest{}, nil, err
		}
		req := gate.ListRequest{
			Token:  bearerToken(r),
			Entity: entity,
			Limit:  limit,
			Offset: offset,
		}
		fetch := func(ctx context.Context, limit, offset int) ([]gate.Record, error) {
			recs, err := store.List(ctx, entity, limit, offset)
			if err != nil {
				return nil, err
			}
			out := make([]gate.Record, len(recs))
			for i, rec := range recs {
				out[i] = gate.Record{ID: rec.ID, Fields: rec.Fields}
			}
			return out, nil
		}
		return req, fetch, nil
	}
}

// parsePageParams reads the optional limit and offset query parameters.
// An absent parameter is zero — the gate then applies its default page
// size and a zero offset. A present-but-unparseable parameter is a
// client error, surfaced so the gated handler answers 400 rather than
// silently serving a different page than the caller asked for.
func parsePageParams(r *http.Request) (limit, offset int, err error) {
	q := r.URL.Query()
	if limit, err = parseIntParam(q.Get("limit")); err != nil {
		return 0, 0, err
	}
	if offset, err = parseIntParam(q.Get("offset")); err != nil {
		return 0, 0, err
	}
	return limit, offset, nil
}

// parseIntParam parses an optional integer query parameter; an empty
// string is zero with no error.
func parseIntParam(raw string) (int, error) {
	if raw == "" {
		return 0, nil
	}
	return strconv.Atoi(raw)
}
