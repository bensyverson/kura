package dashboard

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/bensyverson/kura/internal/cedar"
)

// usersView is the view-model the Users & roles page renders against: the
// authorized list (each user joined to its effective access and any IdP
// mismatch), the roles the policy defines, and an optional banner.
type usersView struct {
	Users    []userView
	AllRoles []string
	Notice   string
	Error    string
}

// userView is one authorized user as the page shows them: the roles held,
// the roles still assignable, their effective access (the policy projected
// to their roles), and an IdP-mismatch status if their provider account no
// longer matches their access.
type userView struct {
	Email      string
	Roles      []string
	Assignable []string
	Effective  *cedar.Policy
	Mismatch   string
}

// handleUsers renders the Users & roles page: it reads the caller's
// identity, the authorized list, the policy, and the IdP mismatches from
// the remote API and assembles them server-side. Any auth problem lands on
// the sign-in prompt; an unreachable remote on the error page.
func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	principal, err := s.api.whoami(r.Context())
	if err != nil {
		s.renderAuthOrError(w, "/users", err)
		return
	}
	users, err := s.api.users(r.Context())
	if err != nil {
		s.renderAuthOrError(w, "/users", err)
		return
	}
	policy, err := s.api.policy(r.Context())
	if err != nil {
		s.renderAuthOrError(w, "/users", err)
		return
	}
	mismatches, err := s.api.mismatches(r.Context())
	if err != nil {
		s.renderAuthOrError(w, "/users", err)
		return
	}

	view := buildUsersView(users, policy, mismatches)
	view.Notice = bannerNotice(r.URL.Query().Get("ok"))
	view.Error = bannerError(r.URL.Query().Get("err"))

	s.render(w, http.StatusOK, "users", pageData{
		Title:     "Users & roles",
		Nav:       navFor("/users"),
		Principal: &principal,
		Users:     &view,
	})
}

// buildUsersView assembles the page's view-model. It makes no policy
// decision: per-user effective access is cedar.Policy.ForRoles (core
// logic); the rest is presentation — joining the mismatch status and
// computing which defined roles a user does not yet hold.
func buildUsersView(users []userRow, policy *cedar.Policy, mismatches []mismatchRow) usersView {
	allRoles := make([]string, 0, len(policy.Roles))
	for _, role := range policy.Roles {
		allRoles = append(allRoles, role.Name)
	}

	mismatchByEmail := make(map[string]string, len(mismatches))
	for _, m := range mismatches {
		mismatchByEmail[m.Email] = m.Status
	}

	view := usersView{AllRoles: allRoles, Users: make([]userView, 0, len(users))}
	for _, u := range users {
		assignable := make([]string, 0)
		for _, role := range allRoles {
			if !slices.Contains(u.Roles, role) {
				assignable = append(assignable, role)
			}
		}
		view.Users = append(view.Users, userView{
			Email:      u.Email,
			Roles:      u.Roles,
			Assignable: assignable,
			Effective:  policy.ForRoles(u.Roles...),
			Mismatch:   mismatchByEmail[u.Email],
		})
	}
	return view
}

// handleAddUser adds a user to the authorized list, then redirects back to
// the page (POST-redirect-GET). It enforces the same-origin guard first.
func (s *Server) handleAddUser(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		http.Error(w, "forbidden: cross-origin request", http.StatusForbidden)
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))
	if email == "" {
		redirectUsers(w, r, "err", "input")
		return
	}
	s.afterMutation(w, r, s.api.addUser(r.Context(), email), "added")
}

// handleRoles assigns or revokes a single role for a user, depending on
// the op form field, then redirects.
func (s *Server) handleRoles(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		http.Error(w, "forbidden: cross-origin request", http.StatusForbidden)
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))
	role := strings.TrimSpace(r.FormValue("role"))
	op := r.FormValue("op")
	if email == "" || role == "" {
		redirectUsers(w, r, "err", "input")
		return
	}
	switch op {
	case "assign":
		s.afterMutation(w, r, s.api.assignRoles(r.Context(), email, role), "assigned")
	case "revoke":
		s.afterMutation(w, r, s.api.revokeRoles(r.Context(), email, role), "revoked")
	default:
		redirectUsers(w, r, "err", "input")
	}
}

// handleDeactivate strips every role from a user, atomically, then
// redirects.
func (s *Server) handleDeactivate(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		http.Error(w, "forbidden: cross-origin request", http.StatusForbidden)
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))
	if email == "" {
		redirectUsers(w, r, "err", "input")
		return
	}
	s.afterMutation(w, r, s.api.deactivateUser(r.Context(), email), "deactivated")
}

// afterMutation completes the POST-redirect-GET: on success it redirects
// with a notice code, on failure with a fixed error code. Codes — not
// remote error text — are what cross the redirect, so nothing
// attacker-influenced is reflected back into the page.
func (s *Server) afterMutation(w http.ResponseWriter, r *http.Request, err error, okCode string) {
	if err == nil {
		redirectUsers(w, r, "ok", okCode)
		return
	}
	switch {
	case errors.Is(err, ErrNotAuthenticated):
		// The session is gone; bounce to /users, which renders sign-in.
		http.Redirect(w, r, "/users", http.StatusSeeOther)
	case errors.Is(err, ErrForbidden):
		redirectUsers(w, r, "err", "forbidden")
	case errors.Is(err, ErrRemoteNotFound):
		redirectUsers(w, r, "err", "notfound")
	default:
		s.cfg.Logger.Error("dashboard: user mutation failed", "err", err)
		redirectUsers(w, r, "err", "unreachable")
	}
}

// redirectUsers issues the 303 back to the users page with one status
// code in the query string.
func redirectUsers(w http.ResponseWriter, r *http.Request, key, code string) {
	http.Redirect(w, r, "/users?"+key+"="+url.QueryEscape(code), http.StatusSeeOther)
}

// sameOrigin reports whether a state-changing request demonstrably came
// from this loopback dashboard itself. The loopback Host allowlist does
// not stop a cross-site form POST — the browser sends our Host, not the
// attacker's — so mutations additionally require an Origin (or, failing
// that, a Referer) whose host is loopback. A request that proves neither
// is refused.
func (s *Server) sameOrigin(r *http.Request) bool {
	if origin := r.Header.Get("Origin"); origin != "" {
		return isLoopbackOriginURL(origin)
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		return isLoopbackOriginURL(ref)
	}
	return false
}

// isLoopbackOriginURL parses an Origin/Referer header value and reports
// whether its host is a loopback address.
func isLoopbackOriginURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	return isLoopbackHost(u.Host)
}

// bannerNotice maps a success code to a fixed, human message. Unknown
// codes yield no banner.
func bannerNotice(code string) string {
	switch code {
	case "added":
		return "User added to the authorized list."
	case "assigned":
		return "Role assigned."
	case "revoked":
		return "Role revoked."
	case "deactivated":
		return "User deactivated — every role revoked."
	default:
		return ""
	}
}

// bannerError maps an error code to a fixed, human message. Mapping codes
// rather than echoing remote text keeps attacker-influenced strings out of
// the page.
func bannerError(code string) string {
	switch code {
	case "input":
		return "Please provide a valid email and role."
	case "forbidden":
		return "You do not have permission to make that change — an admin role is required."
	case "notfound":
		return "That user is not on the authorized list."
	case "unreachable":
		return "Could not reach the Kura server; the change was not made."
	default:
		return ""
	}
}
