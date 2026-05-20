package dashboard

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// auditPageSize bounds how many audit events one page of the viewer shows.
// Pagination is a presentation concern here: the dashboard fetches the
// filtered log from the remote API and slices it for display, newest
// first.
const auditPageSize = 50

// auditView is the view-model the Audit log viewer renders: the current
// page of events (newest first), the filter the operator applied (echoed
// back into the form), an optional input-error banner, and the
// pagination state — prev/next hrefs that carry the same filter forward.
type auditView struct {
	Events  []auditEntry
	Filter  auditFilter
	Error   string
	HasPrev bool
	HasNext bool
	PrevURL string
	NextURL string
	// ShownFrom and ShownTo are the 1-based bounds of the visible page
	// within the filtered total — "showing 1–50 of 137".
	ShownFrom int
	ShownTo   int
	Total     int
}

// handleAudit renders the audit log viewer: it reads the caller's identity,
// then the filtered log from the remote API, and renders one page of events
// server-side. An auth problem lands on sign-in; an unreachable remote on
// the error page. A malformed time bound never reaches the remote — it
// becomes a banner so a typo does not turn into a 502.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	principal, err := s.api.whoami(r.Context())
	if err != nil {
		s.renderAuthOrError(w, "/audit", err)
		return
	}

	q := r.URL.Query()
	filter := auditFilter{
		Actor:  strings.TrimSpace(q.Get("actor")),
		Entity: strings.TrimSpace(q.Get("resource")),
		Action: strings.TrimSpace(q.Get("action")),
		Since:  strings.TrimSpace(q.Get("since")),
		Until:  strings.TrimSpace(q.Get("until")),
	}

	if msg := validateAuditTimes(filter); msg != "" {
		s.render(w, http.StatusOK, "audit", pageData{
			Title:     "Audit log",
			Nav:       navFor("/audit"),
			Principal: &principal,
			Audit:     &auditView{Filter: filter, Error: msg},
		})
		return
	}

	events, err := s.api.audit(r.Context(), filter)
	if err != nil {
		s.renderAuthOrError(w, "/audit", err)
		return
	}

	view := buildAuditView(events, filter, parseOffset(q.Get("offset")))
	s.render(w, http.StatusOK, "audit", pageData{
		Title:     "Audit log",
		Nav:       navFor("/audit"),
		Principal: &principal,
		Audit:     &view,
	})
}

// buildAuditView reverses the append-ordered log to newest-first and slices
// the page at offset. It makes no authorization or masking decision — those
// happened at the gate before the events were returned; this is pure
// presentation. The prev/next hrefs carry the active filter so paging never
// drops it.
func buildAuditView(events []auditEntry, filter auditFilter, offset int) auditView {
	total := len(events)
	reversed := make([]auditEntry, total)
	for i, e := range events {
		reversed[total-1-i] = e
	}

	if offset < 0 || offset >= total {
		offset = 0
	}
	end := min(offset+auditPageSize, total)

	view := auditView{
		Events: reversed[offset:end],
		Filter: filter,
		Total:  total,
	}
	if total > 0 {
		view.ShownFrom = offset + 1
		view.ShownTo = end
	}
	if offset > 0 {
		prev := max(offset-auditPageSize, 0)
		view.HasPrev = true
		view.PrevURL = auditHref(filter, prev)
	}
	if end < total {
		view.HasNext = true
		view.NextURL = auditHref(filter, end)
	}
	return view
}

// auditHref builds a viewer URL that preserves the filter and sets the page
// offset. The entity axis is emitted as the viewer's own "resource"
// parameter (not the wire "entity"), because the link targets this
// dashboard, not the remote API.
func auditHref(f auditFilter, offset int) string {
	q := url.Values{}
	if f.Actor != "" {
		q.Set("actor", f.Actor)
	}
	if f.Entity != "" {
		q.Set("resource", f.Entity)
	}
	if f.Action != "" {
		q.Set("action", f.Action)
	}
	if f.Since != "" {
		q.Set("since", f.Since)
	}
	if f.Until != "" {
		q.Set("until", f.Until)
	}
	q.Set("offset", strconv.Itoa(offset))
	return "/audit?" + q.Encode()
}

// validateAuditTimes checks the optional Since/Until bounds parse as RFC
// 3339 before any are forwarded. It returns a fixed message on the first
// bad bound, or "" when both are absent or valid.
func validateAuditTimes(f auditFilter) string {
	for _, v := range []string{f.Since, f.Until} {
		if v == "" {
			continue
		}
		if _, err := time.Parse(time.RFC3339, v); err != nil {
			return "Time bounds must be RFC 3339, e.g. 2026-05-19T00:00:00Z."
		}
	}
	return ""
}

// parseOffset reads the page offset; a missing or malformed value is 0.
func parseOffset(raw string) int {
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 0
	}
	return n
}
