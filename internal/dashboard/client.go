package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/bensyverson/kura/internal/cedar"
	"github.com/bensyverson/kura/internal/identity"
	"github.com/bensyverson/kura/internal/manifest"
	"github.com/bensyverson/kura/internal/review"
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

// auditEntry is one decoded audit event from GET /api/audit and the row
// the viewer renders. It mirrors the remote API's wire shape — the
// dashboard owns its own view type rather than importing the server's
// response shape. Every field is bounded metadata; there is structurally
// nowhere for a field value to appear, which is the whole point of the
// audit Event type.
type auditEntry struct {
	Time    time.Time `json:"time"`
	Kind    string    `json:"kind"`
	Outcome string    `json:"outcome"`
	Actor   struct {
		Type   string `json:"type"`
		ID     string `json:"id"`
		Email  string `json:"email"`
		Tenant string `json:"tenant"`
	} `json:"actor"`
	Action   string `json:"action"`
	Resource struct {
		Entity string `json:"entity"`
		ID     string `json:"id"`
	} `json:"resource"`
	IP string `json:"ip"`
}

// auditFilter is the set of axes the viewer forwards to GET /api/audit.
// Empty fields are omitted, so the zero filter reads the whole log. Entity
// is the wire param "entity"; the viewer surfaces it to the operator as
// "resource" to match the `kura log --resource` flag.
type auditFilter struct {
	Actor  string
	Entity string
	Action string
	Since  string
	Until  string
}

// audit reads the filtered audit log from GET /api/audit. Filtering is the
// remote gate's query, not a local sieve — the dashboard only forwards the
// axes and renders what comes back.
func (c *apiClient) audit(ctx context.Context, f auditFilter) ([]auditEntry, error) {
	q := url.Values{}
	if f.Actor != "" {
		q.Set("actor", f.Actor)
	}
	if f.Entity != "" {
		q.Set("entity", f.Entity)
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
	path := "/api/audit"
	if enc := q.Encode(); enc != "" {
		path += "?" + enc
	}
	var body struct {
		Events []auditEntry `json:"events"`
	}
	if err := c.getJSON(ctx, path, &body); err != nil {
		return nil, err
	}
	return body.Events, nil
}

// manifest reads the schema manifest from GET /api/manifest — the
// entities, fields (with their PII categories), and relationships the data
// browser renders. The manifest's JSON tags are its wire contract (they
// are the on-disk schema format), so the dashboard decodes the core type
// directly, as it does for cedar.Policy.
func (c *apiClient) manifest(ctx context.Context) (*manifest.Manifest, error) {
	var m manifest.Manifest
	if err := c.getJSON(ctx, "/api/manifest", &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// recordRow is one record from a list or single read: its id and its
// masked fields, exactly as the remote returned them. The dashboard never
// unmasks — masking happened at the gate before these bytes were sent.
type recordRow struct {
	ID     string            `json:"id"`
	Fields map[string]string `json:"fields"`
}

// listRecords reads a masked, bounded page of an entity's records from
// GET /api/{entity}. The gate masks every record to the caller's principal
// before it returns.
func (c *apiClient) listRecords(ctx context.Context, entity string, limit, offset int) ([]recordRow, error) {
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	if offset > 0 {
		q.Set("offset", strconv.Itoa(offset))
	}
	path := "/api/" + url.PathEscape(entity)
	if enc := q.Encode(); enc != "" {
		path += "?" + enc
	}
	var body struct {
		Records []recordRow `json:"records"`
	}
	if err := c.getJSON(ctx, path, &body); err != nil {
		return nil, err
	}
	return body.Records, nil
}

// record reads one masked record from GET /api/{entity}/{id}. The response
// body is the masked field map; the id comes from the path. A missing
// record surfaces as ErrRemoteNotFound.
func (c *apiClient) record(ctx context.Context, entity, id string) (map[string]string, error) {
	var fields map[string]string
	if err := c.getJSON(ctx, "/api/"+url.PathEscape(entity)+"/"+url.PathEscape(id), &fields); err != nil {
		return nil, err
	}
	return fields, nil
}

// startReview starts a new access review on the remote (POST /api/reviews),
// which snapshots the current authorized list, and returns the created
// review so the caller can redirect to its detail page.
func (c *apiClient) startReview(ctx context.Context) (review.Review, error) {
	var r review.Review
	if err := c.postJSON(ctx, "/api/reviews", nil, &r); err != nil {
		return review.Review{}, err
	}
	return r, nil
}

// reviews reads every access review from GET /api/reviews, newest-first.
func (c *apiClient) reviews(ctx context.Context) ([]review.Review, error) {
	var body struct {
		Reviews []review.Review `json:"reviews"`
	}
	if err := c.getJSON(ctx, "/api/reviews", &body); err != nil {
		return nil, err
	}
	return body.Reviews, nil
}

// reviewByID reads one access review (GET /api/reviews/{id}).
func (c *apiClient) reviewByID(ctx context.Context, id string) (review.Review, error) {
	var r review.Review
	if err := c.getJSON(ctx, "/api/reviews/"+url.PathEscape(id), &r); err != nil {
		return review.Review{}, err
	}
	return r, nil
}

// decideReview records an approve/remove decision for one subject
// (POST /api/reviews/{id}/decisions).
func (c *apiClient) decideReview(ctx context.Context, id, email, decision, note string) error {
	return c.do(ctx, http.MethodPost, "/api/reviews/"+url.PathEscape(id)+"/decisions",
		map[string]string{"email": email, "decision": decision, "note": note})
}

// completeReview archives an access review (POST /api/reviews/{id}/complete).
func (c *apiClient) completeReview(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/api/reviews/"+url.PathEscape(id)+"/complete", nil)
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
	case resp.StatusCode == http.StatusNotFound:
		return ErrRemoteNotFound
	default:
		return fmt.Errorf("dashboard: remote API returned status %d", resp.StatusCode)
	}
}

// postJSON performs an authenticated POST against the remote API, marshaling
// body as JSON when non-nil, and decodes the JSON response into out. It maps
// remote statuses the same way getJSON does: 401/403 to ErrNotAuthenticated,
// 404 to ErrRemoteNotFound. It is the write-with-a-response-body sibling of
// do (which discards the body) — used where the dashboard needs the created
// resource back, like the id of a freshly started review.
func (c *apiClient) postJSON(ctx context.Context, path string, body, out any) error {
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, reader)
	if err != nil {
		return fmt.Errorf("dashboard: building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
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
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("dashboard: decoding remote response: %w", err)
		}
		return nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return ErrNotAuthenticated
	case resp.StatusCode == http.StatusNotFound:
		return ErrRemoteNotFound
	default:
		return fmt.Errorf("dashboard: remote API returned status %d", resp.StatusCode)
	}
}
