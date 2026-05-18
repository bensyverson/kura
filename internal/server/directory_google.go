package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/bensyverson/kura/internal/identity"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

// GoogleDirectoryConfig is the Google Admin SDK Directory client
// configuration kura serve needs to look up Workspace account status.
// The credentials file is a service-account JSON key with domain-wide
// delegation enabled in the customer's Workspace admin console; Subject
// is the Workspace admin email the service account impersonates (the
// Admin SDK refuses non-admin subjects).
type GoogleDirectoryConfig struct {
	// CredentialsFile is the path to the service-account JSON key.
	CredentialsFile string
	// Subject is the Workspace admin email to impersonate. The Admin SDK
	// users.get call runs as this admin; impersonation is what lets a
	// service account read directory state without OAuth from a human.
	Subject string
}

// googleDirectoryAPI is the seam over the Admin SDK so the directory's
// status mapping is testable without a live Workspace tenant. The real
// implementation wraps an *admin.Service; tests substitute a fake.
type googleDirectoryAPI interface {
	GetUser(ctx context.Context, email string) (*admin.User, error)
}

// googleDirectory reports Google Workspace account status by calling
// the Admin SDK Directory users.get and mapping the response onto
// identity.AccountStatus. It is the real Directory implementation
// behind identity.Directory; the v1 placeholder is identity.FakeDirectory.
type googleDirectory struct {
	api googleDirectoryAPI
}

var _ identity.Directory = (*googleDirectory)(nil)

// NewGoogleDirectory builds the real Google Workspace Directory client
// from cfg. It requests only the read-only directory user scope — the
// minimum the users.get call needs — so an exfiltrated service-account
// key cannot mutate Workspace state.
//
// The credentials load and OAuth bootstrapping happen here; callers
// should pass a context with a reasonable timeout.
func NewGoogleDirectory(ctx context.Context, cfg GoogleDirectoryConfig) (identity.Directory, error) {
	if cfg.CredentialsFile == "" {
		return nil, fmt.Errorf("server: google directory: CredentialsFile is required")
	}
	if cfg.Subject == "" {
		return nil, fmt.Errorf("server: google directory: Subject (admin email to impersonate) is required")
	}
	creds, err := os.ReadFile(cfg.CredentialsFile)
	if err != nil {
		return nil, fmt.Errorf("server: reading google service-account credentials: %w", err)
	}
	jwtCfg, err := google.JWTConfigFromJSON(creds, admin.AdminDirectoryUserReadonlyScope)
	if err != nil {
		return nil, fmt.Errorf("server: parsing google service-account credentials: %w", err)
	}
	jwtCfg.Subject = cfg.Subject
	svc, err := admin.NewService(ctx, option.WithHTTPClient(jwtCfg.Client(ctx)))
	if err != nil {
		return nil, fmt.Errorf("server: building admin directory service: %w", err)
	}
	return &googleDirectory{api: &googleAdminService{svc: svc}}, nil
}

// AccountStatus maps the Admin SDK users.get response onto identity's
// account states. A 404 from the API is the documented signal that the
// directory has no such user — that is AccountAbsent, not an error.
func (g *googleDirectory) AccountStatus(ctx context.Context, email string) (identity.AccountStatus, error) {
	u, err := g.api.GetUser(ctx, email)
	if err != nil {
		var apiErr *googleapi.Error
		if errors.As(err, &apiErr) && apiErr.Code == http.StatusNotFound {
			return identity.AccountAbsent, nil
		}
		return "", fmt.Errorf("server: google directory lookup for %q: %w", email, err)
	}
	if u.Suspended {
		return identity.AccountSuspended, nil
	}
	return identity.AccountActive, nil
}

// googleAdminService adapts an *admin.Service to googleDirectoryAPI by
// requesting only the suspended field — the one bit of state
// AccountStatus reads.
type googleAdminService struct {
	svc *admin.Service
}

func (g *googleAdminService) GetUser(ctx context.Context, email string) (*admin.User, error) {
	return g.svc.Users.Get(email).Context(ctx).Fields("suspended").Do()
}
