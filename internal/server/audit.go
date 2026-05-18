package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/gate"
	"github.com/bensyverson/kura/internal/identity"
)

// auditLogResource is the resource name every audit-log read is recorded
// against. Reading the audit log is itself an audited event, and it lands
// on its own entity — never "patient" or any data entity — so an auditor
// reviewing the log can tell log reads apart from data reads, and so the
// stream endpoint's own self-events do not masquerade as data activity.
const auditLogResource = "audit_log"

// registerAuditRoutes mounts the audit query and stream endpoints. Both
// are read-only views over the audit subsystem and both run through the
// core gate as AdminReview operations — so reading the audit log is
// authorized against the caller's roles and audited, by construction,
// exactly like the admin review reads. The auditor role and the admin
// role may read; no one writes — the log is append-only, and nothing in
// the API can append to it out of band.
func (s *Server) registerAuditRoutes() {
	s.registerAdmin("GET /api/audit", auditQueryBinding(s.cfg.Audit))
	s.registerAuditStream("GET /api/audit/stream", s.cfg.Audit)
}

// auditEventJSON is the wire shape of one audit Event. It is the adapter's
// own type, not audit.Event with tags bolted on: the wire contract lives
// here, in the adapter, the way recordJSON does for the data routes. Every
// field is bounded metadata — there is structurally nowhere for client
// PII to appear, which is the whole point of the audit Event type.
type auditEventJSON struct {
	Time     time.Time         `json:"time"`
	Kind     string            `json:"kind"`
	Outcome  string            `json:"outcome"`
	Actor    auditActorJSON    `json:"actor"`
	Action   string            `json:"action,omitempty"`
	Resource auditResourceJSON `json:"resource"`
	IP       string            `json:"ip,omitempty"`
}

// auditActorJSON is the wire shape of an event's actor — identifiers only.
type auditActorJSON struct {
	Type   string `json:"type,omitempty"`
	ID     string `json:"id,omitempty"`
	Email  string `json:"email,omitempty"`
	Tenant string `json:"tenant,omitempty"`
}

// auditResourceJSON is the wire shape of an event's resource — an entity
// name and a record id, never a field value.
type auditResourceJSON struct {
	Entity string `json:"entity,omitempty"`
	ID     string `json:"id,omitempty"`
}

// toAuditEventJSON renders one Event into its wire shape.
func toAuditEventJSON(e audit.Event) auditEventJSON {
	return auditEventJSON{
		Time:    e.Time,
		Kind:    string(e.Kind),
		Outcome: string(e.Outcome),
		Actor: auditActorJSON{
			Type:   string(e.Actor.Type),
			ID:     e.Actor.ID,
			Email:  e.Actor.Email,
			Tenant: e.Actor.Tenant,
		},
		Action:   e.Action,
		Resource: auditResourceJSON{Entity: e.Resource.Entity, ID: e.Resource.ID},
		IP:       e.IP,
	}
}

// auditQueryResponse is the body of GET /api/audit: the matching events,
// in append order.
type auditQueryResponse struct {
	Events []auditEventJSON `json:"events"`
}

// auditQueryBinding builds the binding for GET /api/audit: read the audit
// log filtered by actor, resource entity, action, and an
// inclusive-Since / exclusive-Until time window. A review read — the
// auditor may do it. The filter is parsed from the query string; a
// malformed time bound is a client error, surfaced so the handler answers
// 400 rather than silently serving an unfiltered window.
func auditQueryBinding(store audit.Store) adminBinding {
	return func(r *http.Request, _ identity.Principal) (gate.AdminRequest, adminOp, error) {
		filter, err := parseAuditFilter(r)
		if err != nil {
			return gate.AdminRequest{}, nil, err
		}
		req := gate.AdminRequest{
			Token:    bearerToken(r),
			Action:   gate.AdminReview,
			Resource: audit.Resource{Entity: auditLogResource},
		}
		op := func(ctx context.Context) (any, error) {
			events, err := store.Query(ctx, filter)
			if err != nil {
				return nil, err
			}
			out := auditQueryResponse{Events: make([]auditEventJSON, len(events))}
			for i, e := range events {
				out.Events[i] = toAuditEventJSON(e)
			}
			return out, nil
		}
		return req, op, nil
	}
}

// parseAuditFilter reads the audit query parameters into an audit.Filter.
// An absent parameter is "match any"; a present-but-unparseable time
// bound is an error. Time bounds are RFC 3339.
func parseAuditFilter(r *http.Request) (audit.Filter, error) {
	q := r.URL.Query()
	f := audit.Filter{
		Actor:  q.Get("actor"),
		Entity: q.Get("entity"),
		Action: q.Get("action"),
	}
	var err error
	if f.Since, err = parseTimeParam(q.Get("since")); err != nil {
		return audit.Filter{}, err
	}
	if f.Until, err = parseTimeParam(q.Get("until")); err != nil {
		return audit.Filter{}, err
	}
	return f, nil
}

// parseTimeParam parses an optional RFC 3339 time query parameter; an
// empty string is the zero time with no error.
func parseTimeParam(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, raw)
}

// auditStreamHandler serves GET /api/audit/stream: a live JSON-lines feed
// of audit events. It is a gatedRoute — it cannot be mounted under /api/
// otherwise — and it delegates authorization to the core gate before it
// streams a single byte. The query endpoint can be an ordinary
// adminHandler because it has one body to write; the stream cannot,
// because it writes for as long as the client stays connected, so it owns
// its own response loop. It still routes the access decision through
// Gate.Admin, so the stream is authorized and the access is audited the
// same way every other gated route is.
type auditStreamHandler struct {
	gate  *gate.Gate
	store audit.Store
}

func (*auditStreamHandler) gatedThroughCore() {}

// registerAuditStream mounts the audit stream route under /api/. Like the
// data and admin registrars it produces a gatedRoute — an
// *auditStreamHandler — so the route delegates to the core gate by
// construction; apiRoutes cannot hold a handler that does not.
func (s *Server) registerAuditStream(pattern string, store audit.Store) {
	if s.apiRoutes == nil {
		s.apiRoutes = make(map[string]gatedRoute)
	}
	s.apiRoutes[pattern] = &auditStreamHandler{gate: s.cfg.Gate, store: store}
}

// ServeHTTP authorizes the request through the gate, then streams every
// subsequently-appended event as one JSON object per line until the
// client disconnects. Authorization happens first and fails closed: a
// caller without a review role gets a 403 and no stream. Once authorized,
// the subscription is opened before the response headers are flushed, so
// no event appended after the client sees "200 OK" can slip through the
// gap unobserved.
func (h *auditStreamHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if _, ok := principalFromContext(r.Context()); !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	req := gate.AdminRequest{
		Token:    bearerToken(r),
		Action:   gate.AdminReview,
		Resource: audit.Resource{Entity: auditLogResource},
	}
	// The gate authorizes and audits the access; there is no data step to
	// run, so the operation it invokes is a no-op. A denied request never
	// gets past this point.
	if _, err := h.gate.Admin(r.Context(), req, func(context.Context) error { return nil }); err != nil {
		writeGateError(w, err)
		return
	}

	// Subscribe before the headers are flushed: the subscription must be
	// live by the time the client learns the stream is open.
	events := h.store.Subscribe(r.Context())
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}

	enc := json.NewEncoder(w)
	for e := range events {
		if err := enc.Encode(toAuditEventJSON(e)); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}
