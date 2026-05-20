package server

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/data"
	"github.com/bensyverson/kura/internal/gate"
	"github.com/bensyverson/kura/internal/identity"
	"github.com/bensyverson/kura/internal/review"
)

// reviewResource is the resource name every access-review operation is
// audited against — its own entity, so a reviewer reading the audit log can
// tell review activity apart from data access.
const reviewResource = "access_review"

// registerReviewRoutes mounts the access-review endpoints. Starting,
// deciding, and completing a review are AdminManage operations (the admin
// runs the review); listing and reading are AdminReview operations (the
// auditor may also read the artifacts). All run through the core gate, so
// every one is authorized against the caller's roles and audited by
// construction.
func (s *Server) registerReviewRoutes() {
	s.registerAdmin("POST /api/reviews", startReviewBinding(s.cfg.Reviews, s.cfg.Users))
	s.registerAdmin("GET /api/reviews", listReviewsBinding(s.cfg.Reviews))
	s.registerAdmin("GET /api/reviews/{id}", getReviewBinding(s.cfg.Reviews))
	s.registerAdmin("POST /api/reviews/{id}/decisions", decideReviewBinding(s.cfg.Reviews))
	s.registerAdmin("POST /api/reviews/{id}/complete", completeReviewBinding(s.cfg.Reviews))
}

// reviewsListResponse is the body of GET /api/reviews.
type reviewsListResponse struct {
	Reviews []review.Review `json:"reviews"`
}

// decisionRequest is the body of POST /api/reviews/{id}/decisions.
type decisionRequest struct {
	Email    string `json:"email"`
	Decision string `json:"decision"`
	Note     string `json:"note"`
}

// startReviewBinding builds POST /api/reviews: snapshot the current
// authorized list into a new open review, attributed to the caller. An
// AdminManage action — starting a review is management, not just review.
func startReviewBinding(store review.Store, users data.UserStore) adminBinding {
	return func(r *http.Request, p identity.Principal) (gate.AdminRequest, adminOp, error) {
		req := gate.AdminRequest{
			Token:    bearerToken(r),
			Action:   gate.AdminManage,
			Resource: audit.Resource{Entity: reviewResource},
		}
		op := func(ctx context.Context) (any, error) {
			list, err := users.ListUsers(ctx)
			if err != nil {
				return nil, err
			}
			subjects := make([]review.Item, len(list))
			for i, u := range list {
				subjects[i] = review.Item{Email: u.Email, RolesAtReview: u.Roles}
			}
			created, err := store.Create(ctx, p.Email, subjects)
			if err != nil {
				return nil, err
			}
			return created, nil
		}
		return req, op, nil
	}
}

// listReviewsBinding builds GET /api/reviews: every review, newest-first.
func listReviewsBinding(store review.Store) adminBinding {
	return func(r *http.Request, _ identity.Principal) (gate.AdminRequest, adminOp, error) {
		req := gate.AdminRequest{
			Token:    bearerToken(r),
			Action:   gate.AdminReview,
			Resource: audit.Resource{Entity: reviewResource},
		}
		op := func(ctx context.Context) (any, error) {
			reviews, err := store.List(ctx)
			if err != nil {
				return nil, err
			}
			return reviewsListResponse{Reviews: reviews}, nil
		}
		return req, op, nil
	}
}

// getReviewBinding builds GET /api/reviews/{id}: one review artifact.
func getReviewBinding(store review.Store) adminBinding {
	return func(r *http.Request, _ identity.Principal) (gate.AdminRequest, adminOp, error) {
		id := r.PathValue("id")
		req := gate.AdminRequest{
			Token:    bearerToken(r),
			Action:   gate.AdminReview,
			Resource: audit.Resource{Entity: reviewResource, ID: id},
		}
		op := func(ctx context.Context) (any, error) {
			return store.Get(ctx, id)
		}
		return req, op, nil
	}
}

// decideReviewBinding builds POST /api/reviews/{id}/decisions: record an
// approve/remove decision for one subject. An AdminManage action.
func decideReviewBinding(store review.Store) adminBinding {
	return func(r *http.Request, _ identity.Principal) (gate.AdminRequest, adminOp, error) {
		id := r.PathValue("id")
		var body decisionRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return gate.AdminRequest{}, nil, err
		}
		req := gate.AdminRequest{
			Token:    bearerToken(r),
			Action:   gate.AdminManage,
			Resource: audit.Resource{Entity: reviewResource, ID: id},
		}
		op := func(ctx context.Context) (any, error) {
			return nil, store.Decide(ctx, id, body.Email, review.Decision(body.Decision), body.Note)
		}
		return req, op, nil
	}
}

// completeReviewBinding builds POST /api/reviews/{id}/complete: archive the
// review and return the immutable artifact. An AdminManage action.
func completeReviewBinding(store review.Store) adminBinding {
	return func(r *http.Request, _ identity.Principal) (gate.AdminRequest, adminOp, error) {
		id := r.PathValue("id")
		req := gate.AdminRequest{
			Token:    bearerToken(r),
			Action:   gate.AdminManage,
			Resource: audit.Resource{Entity: reviewResource, ID: id},
		}
		op := func(ctx context.Context) (any, error) {
			return store.Complete(ctx, id)
		}
		return req, op, nil
	}
}
