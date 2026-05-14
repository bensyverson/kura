package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// dopplerAPIBaseURL is the public Doppler API. Construction points the
// backend here; tests override DopplerBackend.baseURL.
const dopplerAPIBaseURL = "https://api.doppler.com"

// DopplerBackend is the production Backend: it reads secrets from
// Doppler, the Standard-Regulated secrets backend (decision recorded in
// docs/content/docs/concepts/secrets.md), over Doppler's HTTPS API.
//
// The service token is supplied to the constructor — it is injected at
// runtime by the deployment, never read here from a baked-in env var or
// a committed file. This type has no fallback that reads ambient
// credentials; if the token is not passed in, construction fails.
type DopplerBackend struct {
	token   string
	project string
	config  string

	// baseURL and client are the HTTP target. They default to the
	// public Doppler API and a timeout-bounded client; tests override
	// them to point at a local server.
	baseURL string
	client  *http.Client
}

// NewDopplerBackend returns a DopplerBackend for the given service token,
// project, and config. The token is required and is injected at runtime;
// project and config are required to address the secret store.
func NewDopplerBackend(token, project, config string) (*DopplerBackend, error) {
	if token == "" {
		return nil, ErrMissingToken
	}
	if project == "" || config == "" {
		return nil, ErrMissingDopplerConfig
	}
	return &DopplerBackend{
		token:   token,
		project: project,
		config:  config,
		baseURL: dopplerAPIBaseURL,
		client:  &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// dopplerSecretResponse is the shape of Doppler's single-secret endpoint.
// The computed value is the resolved one (secret references expanded).
type dopplerSecretResponse struct {
	Name  string `json:"name"`
	Value struct {
		Raw      string `json:"raw"`
		Computed string `json:"computed"`
	} `json:"value"`
}

// Fetch returns the computed value of the named secret from Doppler, or
// ErrSecretNotFound if Doppler reports it absent.
func (b *DopplerBackend) Fetch(ctx context.Context, name string) (string, error) {
	q := url.Values{}
	q.Set("project", b.project)
	q.Set("config", b.config)
	q.Set("name", name)
	endpoint := b.baseURL + "/v3/configs/config/secret?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("secrets: building doppler request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+b.token)
	req.Header.Set("Accept", "application/json")

	resp, err := b.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("secrets: doppler request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var parsed dopplerSecretResponse
		if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
			return "", fmt.Errorf("secrets: decoding doppler response: %w", err)
		}
		return parsed.Value.Computed, nil
	case http.StatusNotFound:
		return "", fmt.Errorf("secrets: doppler: %q: %w", name, ErrSecretNotFound)
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
		return "", fmt.Errorf("secrets: doppler returned %s: %s", resp.Status, body)
	}
}
