package secrets

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewDopplerBackendRequiresToken(t *testing.T) {
	if _, err := NewDopplerBackend("", "kura", "prod"); !errors.Is(err, ErrMissingToken) {
		t.Errorf("NewDopplerBackend with empty token err = %v, want ErrMissingToken", err)
	}
}

func TestNewDopplerBackendRequiresProjectAndConfig(t *testing.T) {
	if _, err := NewDopplerBackend("tok", "", "prod"); !errors.Is(err, ErrMissingDopplerConfig) {
		t.Errorf("NewDopplerBackend with empty project err = %v, want ErrMissingDopplerConfig", err)
	}
	if _, err := NewDopplerBackend("tok", "kura", ""); !errors.Is(err, ErrMissingDopplerConfig) {
		t.Errorf("NewDopplerBackend with empty config err = %v, want ErrMissingDopplerConfig", err)
	}
}

func TestDopplerBackendFetchReturnsSecretValue(t *testing.T) {
	var gotAuth, gotProject, gotConfig, gotName string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotProject = r.URL.Query().Get("project")
		gotConfig = r.URL.Query().Get("config")
		gotName = r.URL.Query().Get("name")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"DB_PASSWORD","value":{"raw":"raw-val","computed":"hunter2"}}`))
	}))
	defer srv.Close()

	b, err := NewDopplerBackend("svc-token", "kura", "prod")
	if err != nil {
		t.Fatalf("NewDopplerBackend: %v", err)
	}
	b.baseURL = srv.URL
	b.client = srv.Client()

	got, err := b.Fetch(context.Background(), "DB_PASSWORD")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got != "hunter2" {
		t.Errorf("Fetch = %q, want %q (the computed value)", got, "hunter2")
	}
	if gotAuth != "Bearer svc-token" {
		t.Errorf("Authorization header = %q, want %q", gotAuth, "Bearer svc-token")
	}
	if gotProject != "kura" || gotConfig != "prod" || gotName != "DB_PASSWORD" {
		t.Errorf("query = project:%q config:%q name:%q, want kura/prod/DB_PASSWORD", gotProject, gotConfig, gotName)
	}
}

func TestDopplerBackendFetchMissingSecretReturnsErrSecretNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"messages":["Could not find requested secret"],"success":false}`))
	}))
	defer srv.Close()

	b, _ := NewDopplerBackend("svc-token", "kura", "prod")
	b.baseURL = srv.URL
	b.client = srv.Client()

	if _, err := b.Fetch(context.Background(), "ABSENT"); !errors.Is(err, ErrSecretNotFound) {
		t.Errorf("Fetch missing err = %v, want ErrSecretNotFound", err)
	}
}

func TestDopplerBackendFetchServerErrorReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	b, _ := NewDopplerBackend("svc-token", "kura", "prod")
	b.baseURL = srv.URL
	b.client = srv.Client()

	_, err := b.Fetch(context.Background(), "DB_PASSWORD")
	if err == nil {
		t.Fatal("Fetch against 500: want error, got nil")
	}
	if errors.Is(err, ErrSecretNotFound) {
		t.Errorf("Fetch against 500 err = %v, want a non-ErrSecretNotFound error", err)
	}
}
