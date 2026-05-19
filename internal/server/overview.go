package server

import (
	"context"
	"net/http"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/data"
	"github.com/bensyverson/kura/internal/gate"
	"github.com/bensyverson/kura/internal/identity"
	"github.com/bensyverson/kura/internal/manifest"
)

// overviewStatusOperational is the status the overview reports. The
// endpoint only answers once the request has authenticated, authorized,
// and read every collaborator, so a 200 *is* the proof the system is
// operational; the field carries that fact to the dashboard explicitly.
const overviewStatusOperational = "operational"

// overviewTierPlaceholder mirrors the placeholder `kura status` reports:
// there is no deployment-tier subsystem until Phase 6, but the field is
// present now so the document shape is stable across phases. Its value
// becomes real when the tier subsystem lands, without a schema change.
const overviewTierPlaceholder = "unknown (Phase 6+)"

// overviewRecentLimit bounds how many of the most recent audit events the
// overview carries. The full log is the audit viewer's job; the overview
// shows only the tail.
const overviewRecentLimit = 10

// overviewResponse is the body of GET /api/overview: the dashboard's
// landscape briefing in one read. tier and the access-review / anomaly
// fields are stable placeholders for subsystems that land in later phases
// (Phase 6 tier, the access-review workflow, Phase 8 anomaly detection),
// so the shape does not change when their values become real.
type overviewResponse struct {
	Status         string            `json:"status"`
	Tier           string            `json:"tier"`
	Counts         overviewCounts    `json:"counts"`
	RecentActivity []auditEventJSON  `json:"recent_activity"`
	NeedsAttention overviewAttention `json:"needs_attention"`
}

// overviewCounts is the count panel: how many entities the manifest
// defines, how many records exist (in total and per entity), and how many
// users are on the authorized list.
type overviewCounts struct {
	Entities int                 `json:"entities"`
	Records  int                 `json:"records"`
	Users    int                 `json:"users"`
	ByEntity []entityRecordCount `json:"by_entity"`
}

// entityRecordCount is one entity's record total, in manifest order.
type entityRecordCount struct {
	Entity string `json:"entity"`
	Count  int    `json:"count"`
}

// overviewAttention is the needs-attention panel. IdP mismatches are real
// today — an authorized user whose IdP account is suspended or absent.
// Anomalies is a present-but-empty placeholder until Phase 8 detection
// lands. AccessReviewDue is nil until the access-review workflow lands;
// the dashboard renders that absence as "not yet tracked" rather than a
// false "overdue".
type overviewAttention struct {
	IdPMismatches []data.IdPMismatch `json:"idp_mismatches"`
	Anomalies     []string           `json:"anomalies"`
}

// registerOverviewRoute mounts GET /api/overview. Like every admin route
// it runs through Gate.Admin as an AdminReview operation, so the briefing
// is authorized against the caller's roles and audited by construction —
// the read-only auditor may see it, a plain user may not.
func (s *Server) registerOverviewRoute() {
	s.registerAdmin("GET /api/overview", overviewBinding(s.cfg.Gate, s.cfg.Records, s.cfg.Users, s.cfg.IdP, s.cfg.Audit))
}

// overviewBinding builds the binding for GET /api/overview. The binding
// describes the AdminReview request and supplies the read; the assembly
// itself is delegated to buildOverview, which composes counts, IdP
// mismatches, and recent activity from the core collaborators.
func overviewBinding(g *gate.Gate, records data.RecordStore, users data.UserStore, idp identity.Directory, auditStore audit.Store) adminBinding {
	return func(r *http.Request, _ identity.Principal) (gate.AdminRequest, adminOp, error) {
		req := gate.AdminRequest{
			Token:    bearerToken(r),
			Action:   gate.AdminReview,
			Resource: audit.Resource{Entity: "overview"},
		}
		op := func(ctx context.Context) (any, error) {
			return buildOverview(ctx, g.Manifest(), records, users, idp, auditStore)
		}
		return req, op, nil
	}
}

// buildOverview assembles the briefing from the core collaborators. It
// makes no policy decision and masks nothing — it counts records, counts
// users, detects IdP mismatches (reusing the same detection the
// mismatches endpoint uses), and reads the tail of the audit log. Any
// collaborator error fails the whole read rather than serving a partial,
// misleading briefing.
func buildOverview(ctx context.Context, m *manifest.Manifest, records data.RecordStore, users data.UserStore, idp identity.Directory, auditStore audit.Store) (overviewResponse, error) {
	counts := overviewCounts{
		Entities: len(m.Entities),
		ByEntity: make([]entityRecordCount, 0, len(m.Entities)),
	}
	for _, e := range m.Entities {
		n, err := records.Count(ctx, e.Name)
		if err != nil {
			return overviewResponse{}, err
		}
		counts.ByEntity = append(counts.ByEntity, entityRecordCount{Entity: e.Name, Count: n})
		counts.Records += n
	}

	userList, err := users.ListUsers(ctx)
	if err != nil {
		return overviewResponse{}, err
	}
	counts.Users = len(userList)

	mismatches, err := data.DetectIdPMismatches(ctx, users, idp)
	if err != nil {
		return overviewResponse{}, err
	}
	if mismatches == nil {
		mismatches = []data.IdPMismatch{}
	}

	recent, err := recentActivity(ctx, auditStore, overviewRecentLimit)
	if err != nil {
		return overviewResponse{}, err
	}

	return overviewResponse{
		Status:         overviewStatusOperational,
		Tier:           overviewTierPlaceholder,
		Counts:         counts,
		RecentActivity: recent,
		NeedsAttention: overviewAttention{
			IdPMismatches: mismatches,
			Anomalies:     []string{},
		},
	}, nil
}

// recentActivity reads the audit log and returns at most limit of its
// most recent events, newest first. The store returns events in append
// order, so the tail is the recent slice and reversing it puts the newest
// at the top.
func recentActivity(ctx context.Context, store audit.Store, limit int) ([]auditEventJSON, error) {
	events, err := store.Query(ctx, audit.Filter{})
	if err != nil {
		return nil, err
	}
	out := make([]auditEventJSON, 0, limit)
	for i := len(events) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, toAuditEventJSON(events[i]))
	}
	return out, nil
}
