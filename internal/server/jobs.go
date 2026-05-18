package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/gate"
	"github.com/bensyverson/kura/internal/identity"
	"github.com/bensyverson/kura/internal/jobs"
)

// jobsResource is the resource entity every job operation is audited
// against — submit, list, get all land on it, never on a manifest entity.
// The audit log can tell job activity apart from data activity.
const jobsResource = "job"

// registerJobsRoutes mounts the async-jobs endpoints. Submitting a job
// is an AdminManage operation — only the admin role may enqueue work;
// listing and reading are AdminReview, which the auditor role may do
// too. The ledger is admin-only by design: backups, restores, and
// provisioning are the kinds of jobs the build plan calls out, and
// those have always been the admin's surface.
func (s *Server) registerJobsRoutes() {
	s.registerAdmin("POST /api/jobs", submitJobBinding(s.cfg.Jobs))
	s.registerAdmin("GET /api/jobs", listJobsBinding(s.cfg.Jobs))
	s.registerAdmin("GET /api/jobs/{id}", getJobBinding(s.cfg.Jobs))
}

// submitJobRequest is the wire body of POST /api/jobs.
type submitJobRequest struct {
	Kind           string          `json:"kind"`
	IdempotencyKey string          `json:"idempotency_key"`
	Params         json.RawMessage `json:"params,omitempty"`
}

// submitJobResponse is the wire body of POST /api/jobs. created lets
// the caller tell a fresh submission from a retry-attached one.
type submitJobResponse struct {
	Job     jobs.Job `json:"job"`
	Created bool     `json:"created"`
}

// jobsListResponse is the body of GET /api/jobs.
type jobsListResponse struct {
	Jobs []jobs.Job `json:"jobs"`
}

// submitJobBinding builds the binding for POST /api/jobs. The caller's
// principal email becomes the job's actor — the ledger is actor-scoped
// on submit, so a retry from the same caller with the same key finds
// the existing job rather than spawning a duplicate.
func submitJobBinding(mgr *jobs.Manager) adminBinding {
	return func(r *http.Request, principal identity.Principal) (gate.AdminRequest, adminOp, error) {
		var body submitJobRequest
		if err := decodeJSON(r, &body); err != nil {
			return gate.AdminRequest{}, nil, err
		}
		if body.Kind == "" {
			return gate.AdminRequest{}, nil, errors.New("server: submit job requires a kind")
		}
		if body.IdempotencyKey == "" {
			return gate.AdminRequest{}, nil, errors.New("server: submit job requires an idempotency_key")
		}
		// Reject an unknown kind before we even touch the gate — a 400
		// answer to "this server cannot run a job of that kind", not
		// the gate's generic 500. Authorization still has to pass; the
		// next check returns nil ops, so the handler's binding-error
		// path produces the response.
		if !slicesContains(mgr.Kinds(), body.Kind) {
			return gate.AdminRequest{}, nil, errors.New("server: unknown job kind " + body.Kind)
		}
		actor := actorOf(principal)
		req := gate.AdminRequest{
			Token:    bearerToken(r),
			Action:   gate.AdminManage,
			Resource: audit.Resource{Entity: jobsResource, ID: body.Kind},
		}
		op := func(ctx context.Context) (any, error) {
			j, created, err := mgr.Submit(ctx, actor, body.Kind, body.IdempotencyKey, body.Params)
			if err != nil {
				return nil, err
			}
			return submitJobResponse{Job: j, Created: created}, nil
		}
		return req, op, nil
	}
}

// slicesContains is a local fallback for slices.Contains so this file
// compiles cleanly without dragging an extra import in front of the
// other files in the package — the same idiom appears in gate/admin.go.
func slicesContains(s []string, v string) bool {
	return slices.Contains(s, v)
}

// listJobsBinding builds the binding for GET /api/jobs.
func listJobsBinding(mgr *jobs.Manager) adminBinding {
	return func(r *http.Request, principal identity.Principal) (gate.AdminRequest, adminOp, error) {
		actor := actorOf(principal)
		req := gate.AdminRequest{
			Token:    bearerToken(r),
			Action:   gate.AdminReview,
			Resource: audit.Resource{Entity: jobsResource},
		}
		op := func(ctx context.Context) (any, error) {
			list, err := mgr.List(ctx, actor)
			if err != nil {
				return nil, err
			}
			return jobsListResponse{Jobs: list}, nil
		}
		return req, op, nil
	}
}

// getJobBinding builds the binding for GET /api/jobs/{id}. The ledger
// is actor-scoped on read, so guessing another caller's id resolves to
// ErrJobNotFound, never the other caller's row.
func getJobBinding(mgr *jobs.Manager) adminBinding {
	return func(r *http.Request, principal identity.Principal) (gate.AdminRequest, adminOp, error) {
		id := r.PathValue("id")
		if id == "" {
			return gate.AdminRequest{}, nil, errors.New("server: get job requires an id in the path")
		}
		actor := actorOf(principal)
		req := gate.AdminRequest{
			Token:    bearerToken(r),
			Action:   gate.AdminReview,
			Resource: audit.Resource{Entity: jobsResource, ID: id},
		}
		op := func(ctx context.Context) (any, error) {
			j, err := mgr.Get(ctx, actor, id)
			if err != nil {
				return nil, err
			}
			return j, nil
		}
		return req, op, nil
	}
}

// actorOf returns the actor string a job is stamped with for principal.
// The principal's email is used when present; otherwise (a non-human
// principal — service-to-service flows) the principal ID, lowercased so
// the idempotency join stays case-insensitive.
func actorOf(p identity.Principal) string {
	if p.Email != "" {
		return strings.ToLower(p.Email)
	}
	return strings.ToLower(p.ID)
}
