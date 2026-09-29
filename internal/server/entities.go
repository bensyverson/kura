package server

import (
	"context"
	"encoding/json"
	"fmt"
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
		s.registerEdges("GET /api/"+entity+"/{id}/edges", edgesBindingFor(entity, s.cfg.Edges))
		s.registerIngest("POST /api/"+entity, ingestBindingFor(entity, s.cfg.Records, s.cfg.Writer))
	}
}

// ingestBody is the wire shape of a record-ingestion request: the field
// values to store and, optionally, the relationship edges to create with the
// record. relationships maps a relationship name declared on the entity to
// the ids of the target records it points at; it is omitted when the record
// has none.
type ingestBody struct {
	Fields        map[string]string   `json:"fields"`
	Relationships map[string][]string `json:"relationships,omitempty"`
}

// ingestBindingFor builds the binding for an entity's ingestion route: it
// decodes the request body into fields and relationships and names the gate
// IngestRequest, supplies a RecordExists that resolves relationship targets
// through the read store, and supplies a Writer that persists what the gate
// classified by mapping the gate's WriteRecord onto the store's RecordInput.
// The gate authorizes, validates, scans, and classifies before the Writer
// ever runs.
func ingestBindingFor(entity string, store data.RecordStore, writer data.RecordWriter) ingestBinding {
	return func(r *http.Request, _ identity.Principal) (gate.IngestRequest, gate.RecordExists, gate.Writer, error) {
		var body ingestBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return gate.IngestRequest{}, nil, nil, err
		}
		req := gate.IngestRequest{
			Token:         bearerToken(r),
			Entity:        entity,
			Fields:        body.Fields,
			Relationships: body.Relationships,
		}
		exists := func(ctx context.Context, targetEntity, id string) (bool, error) {
			_, ok, err := store.Get(ctx, targetEntity, id)
			return ok, err
		}
		write := func(ctx context.Context, rec gate.WriteRecord) (string, error) {
			return writer.Insert(ctx, toRecordInput(entity, rec))
		}
		return req, exists, write, nil
	}
}

// toRecordInput maps the gate's decided WriteRecord onto the storage
// layer's RecordInput. It is the seam that keeps the gate import-clean of
// the data package: the gate decides in its own types, the adapter
// translates to the store's.
func toRecordInput(entity string, rec gate.WriteRecord) data.RecordInput {
	in := data.RecordInput{
		Entity:        entity,
		Fields:        make([]data.FieldInput, len(rec.Fields)),
		Spans:         make([]data.SpanInput, len(rec.Spans)),
		Relationships: make([]data.EdgeInput, len(rec.Relationships)),
	}
	for i, f := range rec.Fields {
		in.Fields[i] = data.FieldInput{Name: f.Name, Type: f.Type, Value: f.Value, Encrypted: f.Encrypted}
	}
	for i, e := range rec.Relationships {
		in.Relationships[i] = data.EdgeInput{Relationship: e.Relationship, TargetID: e.TargetID}
	}
	for i, sp := range rec.Spans {
		in.Spans[i] = data.SpanInput{
			Field:      sp.Field,
			Category:   string(sp.Category),
			Offset:     sp.Offset,
			Length:     sp.Length,
			Confidence: sp.Confidence,
		}
	}
	return in
}

// edgesBindingFor builds the binding for an entity's edges route: it reads
// the record id from the path and a required direction query parameter, then
// supplies an EdgesFetcher backed by the edge reader. direction=out reads the
// record's own outgoing edges (the relationships it declared); direction=in
// reads the incoming edges that point at it, which the store orders by the
// source record's sequence. The direction is required — a caller asks for one
// view of a record's connections explicitly, never an implied default.
func edgesBindingFor(entity string, edges data.EdgeReader) edgesBinding {
	return func(r *http.Request, _ identity.Principal) (gate.EdgesRequest, gate.EdgesFetcher, error) {
		id := r.PathValue("id")
		var read func(context.Context, string) ([]data.Edge, error)
		switch r.URL.Query().Get("direction") {
		case "out":
			read = edges.EdgesBySource
		case "in":
			read = edges.EdgesByTarget
		default:
			return gate.EdgesRequest{}, nil, fmt.Errorf("edges: direction query parameter must be \"out\" or \"in\"")
		}
		req := gate.EdgesRequest{
			Token:      bearerToken(r),
			Entity:     entity,
			ResourceID: id,
		}
		fetch := func(ctx context.Context) ([]gate.EdgeView, error) {
			es, err := read(ctx, id)
			if err != nil {
				return nil, err
			}
			views := make([]gate.EdgeView, len(es))
			for i, e := range es {
				views[i] = gate.EdgeView{Relationship: e.Relationship, SourceID: e.SourceID, SourceSeq: e.SourceSeq, TargetID: e.TargetID}
			}
			return views, nil
		}
		return req, fetch, nil
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
		fetch := func(ctx context.Context) (gate.Record, error) {
			rec, ok, err := store.Get(ctx, entity, id)
			if err != nil {
				return gate.Record{}, err
			}
			if !ok {
				return gate.Record{}, data.ErrNotFound
			}
			return gate.Record{ID: rec.ID, Fields: rec.Fields, Erased: rec.Erased}, nil
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
				out[i] = gate.Record{ID: rec.ID, Fields: rec.Fields, Erased: rec.Erased}
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
