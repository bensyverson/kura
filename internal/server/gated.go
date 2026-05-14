package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/bensyverson/kura/internal/gate"
	"github.com/bensyverson/kura/internal/identity"
)

// dataBinding translates an authenticated HTTP request into a gate
// AccessRequest and the Fetcher that reads the underlying record. It is
// the entire contract a data route handler implements: it describes the
// request and supplies the read, and nothing else. It is handed no
// http.ResponseWriter, so it has no way to return a response body that
// did not pass through the gate.
type dataBinding func(r *http.Request, p identity.Principal) (gate.AccessRequest, gate.Fetcher, error)

// gatedHandler is the only handler type mounted under /api/ for data
// routes. It owns the call to Gate.Access and the serialization of the
// masked result; the dataBinding it wraps never touches the
// ResponseWriter. This is the structural form of "the server must not be
// able to serve a data response that bypassed the gate" — a data route
// is a *gatedHandler or it does not exist (see registerData and the
// architectural test).
type gatedHandler struct {
	gate    *gate.Gate
	binding dataBinding
}

// ServeHTTP runs the bound request through the gate and writes the masked
// result as JSON. The binding cannot reach this far with a response of
// its own: it only gets to describe the AccessRequest and the Fetcher,
// and the gate decides whether the fetch runs and what is returned.
func (h *gatedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// requireAuth has already resolved the principal and rejected an
	// unauthenticated request before this handler is reached.
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
		switch {
		case errors.Is(err, gate.ErrDenied):
			http.Error(w, "forbidden", http.StatusForbidden)
		case errors.Is(err, gate.ErrUnknownEntity):
			http.Error(w, "not found", http.StatusNotFound)
		default:
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(res.Fields); err != nil {
		// The status line is already sent; nothing left but to log.
		// The audit Access event was recorded by the gate regardless.
		return
	}
}

// registerData mounts a data route under /api/. It is the only sanctioned
// way to add one: it produces a *gatedHandler, so every route it mounts
// goes through the gate by construction. A route added any other way is
// caught by the architectural test over s.dataRoutes.
func (s *Server) registerData(pattern string, binding dataBinding) {
	if s.dataRoutes == nil {
		s.dataRoutes = make(map[string]http.Handler)
	}
	s.dataRoutes[pattern] = &gatedHandler{gate: s.cfg.Gate, binding: binding}
}
