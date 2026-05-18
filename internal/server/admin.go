package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/data"
	"github.com/bensyverson/kura/internal/gate"
	"github.com/bensyverson/kura/internal/identity"
)

// registerAdminRoutes mounts the user, role, and policy administration
// endpoints. Every one is an adminHandler, so it runs through
// Gate.Admin — authorized against the caller's roles and audited, by
// construction. Mutations need the admin role; the reads — the
// authorized list, effective policy, IdP mismatches — are access-review
// work the auditor may also do. There is deliberately no write route on
// /api/policy: policy authoring stays a repo/PR activity.
func (s *Server) registerAdminRoutes() {
	users := s.cfg.Users
	s.registerAdmin("POST /api/users", addUserBinding(users))
	s.registerAdmin("GET /api/users", listUsersBinding(users))
	s.registerAdmin("DELETE /api/users/{email}", deactivateUserBinding(users))
	s.registerAdmin("POST /api/users/{email}/roles", roleBinding(users, true))
	s.registerAdmin("DELETE /api/users/{email}/roles", roleBinding(users, false))
	s.registerAdmin("GET /api/users/mismatches", mismatchesBinding(users, s.cfg.IdP))
	s.registerAdmin("GET /api/policy", policyBinding(s.cfg.Gate))
}

// usersResponse is the body of GET /api/users.
type usersResponse struct {
	Users []data.User `json:"users"`
}

// mismatchesResponse is the body of GET /api/users/mismatches.
type mismatchesResponse struct {
	Mismatches []data.IdPMismatch `json:"mismatches"`
}

// addUserBinding builds the binding for POST /api/users: add an email to
// the authorized list. A mutation, so it needs the admin role.
func addUserBinding(users data.UserStore) adminBinding {
	return func(r *http.Request, _ identity.Principal) (gate.AdminRequest, adminOp, error) {
		var body struct {
			Email string `json:"email"`
		}
		if err := decodeJSON(r, &body); err != nil {
			return gate.AdminRequest{}, nil, err
		}
		if body.Email == "" {
			return gate.AdminRequest{}, nil, errors.New("server: add user requires an email")
		}
		req := gate.AdminRequest{
			Token:    bearerToken(r),
			Action:   gate.AdminManage,
			Resource: audit.Resource{Entity: "user", ID: body.Email},
		}
		op := func(ctx context.Context) (any, error) {
			return nil, users.AddUser(ctx, body.Email)
		}
		return req, op, nil
	}
}

// listUsersBinding builds the binding for GET /api/users: read the
// authorized list with role assignments. A review read.
func listUsersBinding(users data.UserStore) adminBinding {
	return func(r *http.Request, _ identity.Principal) (gate.AdminRequest, adminOp, error) {
		req := gate.AdminRequest{
			Token:    bearerToken(r),
			Action:   gate.AdminReview,
			Resource: audit.Resource{Entity: "user"},
		}
		op := func(ctx context.Context) (any, error) {
			list, err := users.ListUsers(ctx)
			if err != nil {
				return nil, err
			}
			return usersResponse{Users: list}, nil
		}
		return req, op, nil
	}
}

// deactivateUserBinding builds the binding for DELETE /api/users/{email}:
// atomically revoke every role the user holds, leaving them on the
// authorized list. A mutation, so it needs the admin role; the store's
// own atomicity is what keeps the role-strip all-or-nothing.
func deactivateUserBinding(users data.UserStore) adminBinding {
	return func(r *http.Request, _ identity.Principal) (gate.AdminRequest, adminOp, error) {
		email := r.PathValue("email")
		if email == "" {
			return gate.AdminRequest{}, nil, errors.New("server: deactivate user requires an email in the path")
		}
		req := gate.AdminRequest{
			Token:    bearerToken(r),
			Action:   gate.AdminManage,
			Resource: audit.Resource{Entity: "user", ID: email},
		}
		op := func(ctx context.Context) (any, error) {
			return nil, users.DeactivateUser(ctx, email)
		}
		return req, op, nil
	}
}

// roleBinding builds the binding for the role assign/revoke routes. assign
// chooses the direction. Both are mutations, so both need the admin role;
// the role set is applied atomically by the store.
func roleBinding(users data.UserStore, assign bool) adminBinding {
	return func(r *http.Request, _ identity.Principal) (gate.AdminRequest, adminOp, error) {
		email := r.PathValue("email")
		var body struct {
			Roles []string `json:"roles"`
		}
		if err := decodeJSON(r, &body); err != nil {
			return gate.AdminRequest{}, nil, err
		}
		req := gate.AdminRequest{
			Token:    bearerToken(r),
			Action:   gate.AdminManage,
			Resource: audit.Resource{Entity: "role_assignment", ID: email},
		}
		op := func(ctx context.Context) (any, error) {
			if assign {
				return nil, users.AssignRoles(ctx, email, body.Roles...)
			}
			return nil, users.RevokeRoles(ctx, email, body.Roles...)
		}
		return req, op, nil
	}
}

// mismatchesBinding builds the binding for GET /api/users/mismatches:
// cross-check the authorized list against the identity provider. A
// review read.
func mismatchesBinding(users data.UserStore, idp identity.Directory) adminBinding {
	return func(r *http.Request, _ identity.Principal) (gate.AdminRequest, adminOp, error) {
		req := gate.AdminRequest{
			Token:    bearerToken(r),
			Action:   gate.AdminReview,
			Resource: audit.Resource{Entity: "idp_mismatch"},
		}
		op := func(ctx context.Context) (any, error) {
			ms, err := data.DetectIdPMismatches(ctx, users, idp)
			if err != nil {
				return nil, err
			}
			return mismatchesResponse{Mismatches: ms}, nil
		}
		return req, op, nil
	}
}

// policyBinding builds the binding for GET /api/policy: render the
// effective authorization policy. A review read — and read-only: the
// route table has no write method on /api/policy.
func policyBinding(g *gate.Gate) adminBinding {
	return func(r *http.Request, _ identity.Principal) (gate.AdminRequest, adminOp, error) {
		req := gate.AdminRequest{
			Token:    bearerToken(r),
			Action:   gate.AdminReview,
			Resource: audit.Resource{Entity: "policy"},
		}
		op := func(_ context.Context) (any, error) {
			return g.Policy(), nil
		}
		return req, op, nil
	}
}

// decodeJSON decodes the request body into v. A nil body — possible only
// on a directly-constructed request, never one served over HTTP — is a
// bad request, not a panic.
func decodeJSON(r *http.Request, v any) error {
	if r.Body == nil {
		return errors.New("server: missing request body")
	}
	return json.NewDecoder(r.Body).Decode(v)
}
