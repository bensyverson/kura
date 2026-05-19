package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/bensyverson/kura/internal/identity"
)

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
