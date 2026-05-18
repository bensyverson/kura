package server

import "net/http"

// whoamiHandler serves GET /api/whoami: the minimal self-identity read
// behind requireAuth. The authentication middleware already resolved
// the bearer token to a Cedar principal and recorded the auth event;
// whoami's job is to surface that principal so the caller can confirm
// who the server sees them as. No additional gate decision is needed —
// reading your own identity is implicit in being authenticated.
//
// It satisfies gatedRoute because requireAuth is the gate that matters
// here: an unauthenticated request never reaches the handler at all,
// and the auth event the recorder writes covers the access.
type whoamiHandler struct{}

func (*whoamiHandler) gatedThroughCore() {}

// ServeHTTP returns the resolved principal as JSON, or 401 if the
// request did not pass through requireAuth (defense in depth — the
// middleware would normally have refused it already).
func (h *whoamiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	writeJSON(w, principal)
}

// registerWhoami mounts /api/whoami. Like the data registrars, it
// produces a gatedRoute — a *whoamiHandler — so the route satisfies the
// architectural invariant that no non-gated handler can live under
// /api/.
func (s *Server) registerWhoami() {
	if s.apiRoutes == nil {
		s.apiRoutes = make(map[string]gatedRoute)
	}
	s.apiRoutes["GET /api/whoami"] = &whoamiHandler{}
}
