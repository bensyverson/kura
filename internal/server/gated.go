package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/bensyverson/kura/internal/data"
	"github.com/bensyverson/kura/internal/gate"
	"github.com/bensyverson/kura/internal/identity"
	"github.com/bensyverson/kura/internal/jobs"
)

// gatedRoute is the interface every route mounted under /api/ must
// satisfy. Its unexported marker method means a type satisfies it only
// by being defined in this package — and the only types here that do are
// the gated handlers, each a thin wrapper that delegates to the core
// gate. registerData, registerListData, and registerAdmin are the only
// constructors; apiRoutes is typed as a map of gatedRoute, so a raw
// http.Handler cannot even be stored as a route. The architectural test
// asserts the invariant a second time, with teeth.
type gatedRoute interface {
	http.Handler
	gatedThroughCore()
}

// dataBinding translates an authenticated HTTP request into a gate
// AccessRequest and the Fetcher that reads the underlying record. It is
// the entire contract a get-route handler implements: it describes the
// request and supplies the read, and nothing else. It is handed no
// http.ResponseWriter, so it has no way to return a response body that
// did not pass through the gate.
type dataBinding func(r *http.Request, p identity.Principal) (gate.AccessRequest, gate.Fetcher, error)

// listBinding is dataBinding's list-shaped sibling: it describes a gate
// ListRequest and supplies the ListFetcher. Like dataBinding, it never
// touches the ResponseWriter.
type listBinding func(r *http.Request, p identity.Principal) (gate.ListRequest, gate.ListFetcher, error)

// gatedHandler serves a single record. It owns the call to Gate.Access
// and the serialization of the masked result; the dataBinding it wraps
// never touches the ResponseWriter.
type gatedHandler struct {
	gate    *gate.Gate
	binding dataBinding
}

func (*gatedHandler) gatedThroughCore() {}

// ServeHTTP runs the bound request through the gate and writes the masked
// record as JSON. The binding only describes the AccessRequest and the
// Fetcher; the gate decides whether the fetch runs and what comes back.
func (h *gatedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	req, fetch, err := h.binding(r, principal)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	res, err := h.gate.Access(r.Context(), req, fetch)
	if err != nil {
		writeGateError(w, err)
		return
	}
	writeJSON(w, res.Fields)
}

// gatedListHandler serves a bounded, masked page of records. It owns the
// call to Gate.List and the serialization of the result; the listBinding
// it wraps never touches the ResponseWriter.
type gatedListHandler struct {
	gate    *gate.Gate
	binding listBinding
}

func (*gatedListHandler) gatedThroughCore() {}

// recordJSON is one record in a list response: its id and its masked
// fields.
type recordJSON struct {
	ID     string            `json:"id"`
	Fields map[string]string `json:"fields"`
}

// listResponse is the body of a list endpoint: the masked page plus the
// effective limit and offset the gate actually applied, so a client can
// page without guessing what bounds it got.
type listResponse struct {
	Records []recordJSON `json:"records"`
	Limit   int          `json:"limit"`
	Offset  int          `json:"offset"`
}

// ServeHTTP runs the bound list request through the gate and writes the
// masked page as JSON.
func (h *gatedListHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	req, fetch, err := h.binding(r, principal)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	res, err := h.gate.List(r.Context(), req, fetch)
	if err != nil {
		writeGateError(w, err)
		return
	}
	out := listResponse{Records: make([]recordJSON, len(res.Records)), Limit: res.Limit, Offset: res.Offset}
	for i, rec := range res.Records {
		out.Records[i] = recordJSON{ID: rec.ID, Fields: rec.Fields}
	}
	writeJSON(w, out)
}

// adminBinding translates an authenticated request into a gate
// AdminRequest and the operation to run under it once authorization
// passes. Like the data bindings it never touches the ResponseWriter:
// it describes the request and supplies the operation, and the handler
// serializes whatever the operation returns.
type adminBinding func(r *http.Request, p identity.Principal) (gate.AdminRequest, adminOp, error)

// adminOp is the operation an adminBinding hands the gate. The gate runs
// it only after the admin authorization passes; its result — nil for a
// mutation with no body — is what the handler serializes.
type adminOp func(ctx context.Context) (any, error)

// adminHandler serves a user/role/policy administrative endpoint. It
// owns the call to Gate.Admin; the adminBinding it wraps never touches
// the ResponseWriter.
type adminHandler struct {
	gate    *gate.Gate
	binding adminBinding
}

func (*adminHandler) gatedThroughCore() {}

// ServeHTTP runs the bound admin request through the gate and serializes
// the operation's result. The gate authorizes, runs the operation, and
// audits it; the handler only renders the outcome.
func (h *adminHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	req, op, err := h.binding(r, principal)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var result any
	if _, err := h.gate.Admin(r.Context(), req, func(ctx context.Context) error {
		var opErr error
		result, opErr = op(ctx)
		return opErr
	}); err != nil {
		writeGateError(w, err)
		return
	}
	if result == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, result)
}

// writeGateError maps an error from the gate to an HTTP status. A denied
// request is a 403; an unknown entity, a missing record, or a user not
// on the authorized list is a 404; anything else is a 500 — the gate
// does not leak why past these.
func writeGateError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, gate.ErrDenied):
		http.Error(w, "forbidden", http.StatusForbidden)
	case errors.Is(err, gate.ErrUnknownEntity),
		errors.Is(err, data.ErrNotFound),
		errors.Is(err, data.ErrUserNotFound),
		errors.Is(err, jobs.ErrJobNotFound):
		http.Error(w, "not found", http.StatusNotFound)
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// writeJSON writes v as a JSON response body. A failure to encode comes
// after the status line is already sent, so there is nothing left to do
// but stop — the gate already recorded the audit event regardless.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// registerData mounts a single-record route under /api/. It is one of
// the two sanctioned ways to add a data route: it produces a
// *gatedHandler, so the route goes through the gate by construction.
func (s *Server) registerData(pattern string, binding dataBinding) {
	if s.apiRoutes == nil {
		s.apiRoutes = make(map[string]gatedRoute)
	}
	s.apiRoutes[pattern] = &gatedHandler{gate: s.cfg.Gate, binding: binding}
}

// registerListData mounts a list route under /api/. Like registerData,
// it produces a gated handler — a *gatedListHandler — so the route goes
// through the gate by construction.
func (s *Server) registerListData(pattern string, binding listBinding) {
	if s.apiRoutes == nil {
		s.apiRoutes = make(map[string]gatedRoute)
	}
	s.apiRoutes[pattern] = &gatedListHandler{gate: s.cfg.Gate, binding: binding}
}

// registerAdmin mounts an administrative route under /api/. Like the
// data registrars it produces a gated handler — a *adminHandler — so the
// route delegates to Gate.Admin by construction.
func (s *Server) registerAdmin(pattern string, binding adminBinding) {
	if s.apiRoutes == nil {
		s.apiRoutes = make(map[string]gatedRoute)
	}
	s.apiRoutes[pattern] = &adminHandler{gate: s.cfg.Gate, binding: binding}
}
