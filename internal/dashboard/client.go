package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/bensyverson/kura/internal/cedar"
	"github.com/bensyverson/kura/internal/identity"
)

// ErrForbidden is the remote refusing a request the caller authenticated
// for but is not authorized to make — a non-admin attempting a user/role
// mutation. It is distinct from ErrNotAuthenticated: re-running `kura
// login` will not help, so the dashboard surfaces it as a permission
// error rather than a sign-in prompt.
var ErrForbidden = errors.New("dashboard: the remote refused this action (admin role required)")

// ErrRemoteNotFound is the remote reporting the target of a mutation does
// not exist — e.g. assigning a role to an email not on the authorized
// list.
var ErrRemoteNotFound = errors.New("dashboard: the remote could not find that user")

// apiClient is the dashboard's server-side reader of the remote kura
// serve JSON API. It is the only path the dashboard has to data: there
// is no database seam here by construction, so every rendered byte comes
// from the remote API (criterion IK2). The cached bearer token is read
// per request and attached server-side; it never reaches the browser.
type apiClient struct {
	base   string
	tokens TokenSource
	http   *http.Client
}

// whoami reads the caller's resolved principal from /api/whoami.
func (c *apiClient) whoami(ctx context.Context) (identity.Principal, error) {
	var p identity.Principal
	if err := c.getJSON(ctx, "/api/whoami", &p); err != nil {
		return identity.Principal{}, err
	}
	return p, nil
}

// overview reads the dashboard's landscape briefing from /api/overview:
// system status, deployment tier, record/user counts, recent activity,
// and the needs-attention panel. The shapes below mirror the remote API's
// wire contract — the dashboard is a separate client, so it owns its own
// view-model rather than importing the server's response types.
func (c *apiClient) overview(ctx context.Context) (overviewData, error) {
	var o overviewData
	if err := c.getJSON(ctx, "/api/overview", &o); err != nil {
		return overviewData{}, err
	}
	return o, nil
}

// overviewData is the decoded /api/overview body and the view-model the
// overview page renders against.
type overviewData struct {
	Status         string            `json:"status"`
	Tier           string            `json:"tier"`
	Counts         overviewCounts    `json:"counts"`
	RecentActivity []overviewEvent   `json:"recent_activity"`
	NeedsAttention overviewAttention `json:"needs_attention"`
}

// overviewCounts is the count panel: entities defined, records stored (in
// total and per entity), and authorized users.
type overviewCounts struct {
	Entities int                   `json:"entities"`
	Records  int                   `json:"records"`
	Users    int                   `json:"users"`
	ByEntity []overviewEntityCount `json:"by_entity"`
}

// overviewEntityCount is one entity's record total.
type overviewEntityCount struct {
	Entity string `json:"entity"`
	Count  int    `json:"count"`
}

// overviewEvent is one recent audit event — bounded metadata only, never
// a field value.
type overviewEvent struct {
	Time     time.Time        `json:"time"`
	Kind     string           `json:"kind"`
	Outcome  string           `json:"outcome"`
	Actor    overviewActor    `json:"actor"`
	Action   string           `json:"action"`
	Resource overviewResource `json:"resource"`
}

// overviewActor identifies who performed an event — identifiers only.
type overviewActor struct {
	Type  string `json:"type"`
	ID    string `json:"id"`
	Email string `json:"email"`
}

// overviewResource names what an event concerned — an entity and id.
type overviewResource struct {
	Entity string `json:"entity"`
	ID     string `json:"id"`
}

// overviewAttention is the needs-attention panel. IdP mismatches are live
// today; anomalies is a present-but-empty placeholder until the detection
// subsystem lands.
type overviewAttention struct {
	IdPMismatches []overviewMismatch `json:"idp_mismatches"`
	Anomalies     []string           `json:"anomalies"`
}

// overviewMismatch is one authorized user whose IdP account no longer
// matches their access — suspended or absent while still holding roles.
type overviewMismatch struct {
	Email  string   `json:"email"`
	Roles  []string `json:"roles"`
	Status string   `json:"status"`
}

// userRow is one entry of GET /api/users: an authorized email and the
// role names it holds. It mirrors the remote's data.User wire shape.
type userRow struct {
	Email string   `json:"email"`
	Roles []string `json:"roles"`
}

// mismatchRow is one entry of GET /api/users/mismatches: an authorized
// user whose identity-provider account no longer matches their access.
type mismatchRow struct {
	Email  string   `json:"email"`
	Roles  []string `json:"roles"`
	Status string   `json:"status"`
}

// users reads the authorized-user list with role assignments from
// GET /api/users.
func (c *apiClient) users(ctx context.Context) ([]userRow, error) {
	var body struct {
		Users []userRow `json:"users"`
	}
	if err := c.getJSON(ctx, "/api/users", &body); err != nil {
		return nil, err
	}
	return body.Users, nil
}

// policy reads the effective authorization policy (the Cedar IR) from
// GET /api/policy. The IR is the read-only model the dashboard renders;
// per-user effective access is a projection of it (cedar.Policy.ForRoles).
func (c *apiClient) policy(ctx context.Context) (*cedar.Policy, error) {
	var p cedar.Policy
	if err := c.getJSON(ctx, "/api/policy", &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// mismatches reads the IdP mismatch list from GET /api/users/mismatches.
func (c *apiClient) mismatches(ctx context.Context) ([]mismatchRow, error) {
	var body struct {
		Mismatches []mismatchRow `json:"mismatches"`
	}
	if err := c.getJSON(ctx, "/api/users/mismatches", &body); err != nil {
		return nil, err
	}
	return body.Mismatches, nil
}

// addUser adds email to the remote authorized list (POST /api/users).
func (c *apiClient) addUser(ctx context.Context, email string) error {
	return c.do(ctx, http.MethodPost, "/api/users", map[string]string{"email": email})
}

// assignRoles grants roles to email on the remote
// (POST /api/users/{email}/roles).
func (c *apiClient) assignRoles(ctx context.Context, email string, roles ...string) error {
	return c.do(ctx, http.MethodPost, c.userRolesPath(email), map[string][]string{"roles": roles})
}

// revokeRoles removes roles from email on the remote
// (DELETE /api/users/{email}/roles).
func (c *apiClient) revokeRoles(ctx context.Context, email string, roles ...string) error {
	return c.do(ctx, http.MethodDelete, c.userRolesPath(email), map[string][]string{"roles": roles})
}

// deactivateUser strips every role from email on the remote, atomically
// (DELETE /api/users/{email}).
func (c *apiClient) deactivateUser(ctx context.Context, email string) error {
	return c.do(ctx, http.MethodDelete, "/api/users/"+url.PathEscape(email), nil)
}

// userRolesPath builds the remote role-endpoint path for an email, with
// the email escaped as a single path segment.
func (c *apiClient) userRolesPath(email string) string {
	return "/api/users/" + url.PathEscape(email) + "/roles"
}

// do performs an authenticated state-changing request against the remote
// API, marshaling body as JSON when non-nil. A missing token or a 401 is
// ErrNotAuthenticated; a 403 is ErrForbidden; a 404 is ErrRemoteNotFound;
// any other non-2xx is a remote error. A 2xx (the mutations answer 204)
// is success.
func (c *apiClient) do(ctx context.Context, method, path string, body any) error {
	token, err := c.tokens.Token()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNotAuthenticated, err)
	}
	var reader *bytes.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("dashboard: encoding request body: %w", err)
		}
		reader = bytes.NewReader(buf)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return fmt.Errorf("dashboard: building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("dashboard: calling remote API: %w", err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusUnauthorized:
		return ErrNotAuthenticated
	case resp.StatusCode == http.StatusForbidden:
		return ErrForbidden
	case resp.StatusCode == http.StatusNotFound:
		return ErrRemoteNotFound
	default:
		return fmt.Errorf("dashboard: remote API returned status %d", resp.StatusCode)
	}
}

// getJSON performs an authenticated GET against the remote API and
// decodes a JSON body into out. A missing token, or a 401/403 from the
// remote, becomes ErrNotAuthenticated so the caller can render the
// sign-in prompt; any other non-200 is a remote-unavailable error.
func (c *apiClient) getJSON(ctx context.Context, path string, out any) error {
	token, err := c.tokens.Token()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNotAuthenticated, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return fmt.Errorf("dashboard: building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("dashboard: calling remote API: %w", err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusOK:
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("dashboard: decoding remote response: %w", err)
		}
		return nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return ErrNotAuthenticated
	default:
		return fmt.Errorf("dashboard: remote API returned status %d", resp.StatusCode)
	}
}
