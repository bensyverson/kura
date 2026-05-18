package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/bensyverson/kura/internal/identity"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// MicrosoftDirectoryConfig is the Microsoft Graph client configuration
// kura serve needs to look up Entra account status. App-only auth
// (client credentials) is the right mode here: the directory lookup
// runs as the application, not as any signed-in user, so it returns
// consistent answers independent of who is asking.
type MicrosoftDirectoryConfig struct {
	// TenantID is the Entra tenant whose directory will be queried — the
	// directory of the firm or client this deployment serves. Unlike the
	// sign-in IdP, "common" is not meaningful here: the directory is
	// always a specific tenant.
	TenantID string
	// ClientID is the application (client) ID of the Entra app
	// registration that has User.Read.All (application) permission
	// granted with admin consent.
	ClientID string
	// ClientSecret is the corresponding client secret value.
	ClientSecret string
}

// microsoftDirectoryAPI is the seam over the Microsoft Graph users.get
// call so microsoftDirectory's status mapping is testable without a
// live Entra tenant. The real implementation is graphHTTPAPI; tests
// substitute a fake.
type microsoftDirectoryAPI interface {
	GetUser(ctx context.Context, email string) (*microsoftDirectoryUser, error)
}

// microsoftDirectoryUser is the Kura-side projection of the single
// Graph property AccountStatus reads.
type microsoftDirectoryUser struct {
	AccountEnabled bool `json:"accountEnabled"`
}

// errMicrosoftUserNotFound is the sentinel a Graph 404 maps to so
// AccountStatus can convert it to AccountAbsent without inspecting
// transport-level error shapes.
var errMicrosoftUserNotFound = errors.New("server: microsoft directory: user not found")

// microsoftDirectory reports Entra account status by calling Microsoft
// Graph and mapping the response onto identity.AccountStatus. It is
// the real Directory implementation behind identity.Directory; the v1
// placeholder is identity.FakeDirectory.
type microsoftDirectory struct {
	api microsoftDirectoryAPI
}

var _ identity.Directory = (*microsoftDirectory)(nil)

// NewMicrosoftDirectory builds the real Microsoft Graph directory
// client from cfg. Authentication is OAuth client credentials against
// the configured tenant; the only Graph scope used is `.default`,
// which resolves to the application permissions granted at app
// registration. The minimum-privilege grant Kura needs is
// User.Read.All (application).
func NewMicrosoftDirectory(ctx context.Context, cfg MicrosoftDirectoryConfig) (identity.Directory, error) {
	if cfg.TenantID == "" {
		return nil, fmt.Errorf("server: microsoft directory: TenantID is required")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("server: microsoft directory: ClientID is required")
	}
	if cfg.ClientSecret == "" {
		return nil, fmt.Errorf("server: microsoft directory: ClientSecret is required")
	}
	ccCfg := &clientcredentials.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		TokenURL:     "https://login.microsoftonline.com/" + cfg.TenantID + "/oauth2/v2.0/token",
		Scopes:       []string{"https://graph.microsoft.com/.default"},
	}
	return &microsoftDirectory{api: &graphHTTPAPI{
		client:  http.DefaultClient,
		baseURL: "https://graph.microsoft.com",
		token:   ccCfg.TokenSource(ctx),
	}}, nil
}

// AccountStatus maps a Graph users.get response onto identity's
// account states. accountEnabled=true is the active path; false is
// AccountSuspended (Entra calls the same state "blocked sign-in");
// the not-found sentinel is AccountAbsent.
func (m *microsoftDirectory) AccountStatus(ctx context.Context, email string) (identity.AccountStatus, error) {
	u, err := m.api.GetUser(ctx, email)
	if err != nil {
		if errors.Is(err, errMicrosoftUserNotFound) {
			return identity.AccountAbsent, nil
		}
		return "", fmt.Errorf("server: microsoft directory lookup for %q: %w", email, err)
	}
	if !u.AccountEnabled {
		return identity.AccountSuspended, nil
	}
	return identity.AccountActive, nil
}

// graphHTTPAPI is the real microsoftDirectoryAPI: a thin HTTP client
// over Microsoft Graph's GET /v1.0/users/{email}?$select=accountEnabled.
// It is the untestable seam by design; the fake in the tests stands in
// for exactly this type.
type graphHTTPAPI struct {
	client  *http.Client
	baseURL string
	token   oauth2.TokenSource
}

// GetUser calls Graph's user-get endpoint for email, requesting only
// the accountEnabled property. A 404 is mapped to errMicrosoftUserNotFound;
// any other non-2xx is a transport error.
func (g *graphHTTPAPI) GetUser(ctx context.Context, email string) (*microsoftDirectoryUser, error) {
	tok, err := g.token.Token()
	if err != nil {
		return nil, fmt.Errorf("server: graph: obtaining access token: %w", err)
	}
	endpoint := g.baseURL + "/v1.0/users/" + url.PathEscape(email) + "?$select=accountEnabled"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("server: graph: building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("server: graph: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, errMicrosoftUserNotFound
	}
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("server: graph: GET /users returned %d: %s", resp.StatusCode, string(body))
	}
	var out microsoftDirectoryUser
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("server: graph: decoding response: %w", err)
	}
	return &out, nil
}
