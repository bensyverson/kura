package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

// fakeAdminServer is a small stand-in for `kura serve`'s admin surface,
// enough to drive `kura user`/`kura role` end-to-end. It records every
// request it sees so a test can pin not just the rendered output but
// also the variadic-and-atomic call shape — N emails should fan out
// to N admin calls, each idempotent at the data layer.
type fakeAdminServer struct {
	t         *testing.T
	mu        sync.Mutex
	users     map[string][]string // email -> roles (lower-case)
	requests  []adminCall
	policy    json.RawMessage // raw to keep the test independent of cedar.Policy's shape
	authToken string
}

type adminCall struct {
	method string
	path   string
	body   string
}

func newFakeAdminServer(t *testing.T) *fakeAdminServer {
	return &fakeAdminServer{
		t:     t,
		users: make(map[string][]string),
	}
}

func (f *fakeAdminServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/whoami", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type": "admin", "id": "admin@client.com", "email": "admin@client.com", "tenant": "client.com",
		})
	})
	mux.HandleFunc("GET /api/users", func(w http.ResponseWriter, r *http.Request) {
		f.record(r, "")
		f.mu.Lock()
		defer f.mu.Unlock()
		type u struct {
			Email string   `json:"email"`
			Roles []string `json:"roles"`
		}
		out := struct {
			Users []u `json:"users"`
		}{}
		for email, roles := range f.users {
			out.Users = append(out.Users, u{Email: email, Roles: append([]string(nil), roles...)})
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /api/users", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.record(r, string(body))
		var b struct {
			Email string `json:"email"`
		}
		_ = json.Unmarshal(body, &b)
		f.mu.Lock()
		defer f.mu.Unlock()
		if _, ok := f.users[strings.ToLower(b.Email)]; !ok {
			f.users[strings.ToLower(b.Email)] = nil
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("DELETE /api/users/{email}", func(w http.ResponseWriter, r *http.Request) {
		f.record(r, "")
		email := strings.ToLower(r.PathValue("email"))
		f.mu.Lock()
		defer f.mu.Unlock()
		if _, ok := f.users[email]; !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		f.users[email] = nil
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /api/users/{email}/roles", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.record(r, string(body))
		email := strings.ToLower(r.PathValue("email"))
		var b struct {
			Roles []string `json:"roles"`
		}
		_ = json.Unmarshal(body, &b)
		f.mu.Lock()
		defer f.mu.Unlock()
		held, ok := f.users[email]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		for _, r := range b.Roles {
			present := slices.Contains(held, r)
			if !present {
				held = append(held, r)
			}
		}
		f.users[email] = held
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("DELETE /api/users/{email}/roles", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.record(r, string(body))
		email := strings.ToLower(r.PathValue("email"))
		var b struct {
			Roles []string `json:"roles"`
		}
		_ = json.Unmarshal(body, &b)
		f.mu.Lock()
		defer f.mu.Unlock()
		held, ok := f.users[email]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		kept := held[:0:0]
		for _, h := range held {
			drop := slices.Contains(b.Roles, h)
			if !drop {
				kept = append(kept, h)
			}
		}
		f.users[email] = kept
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /api/policy", func(w http.ResponseWriter, r *http.Request) {
		f.record(r, "")
		if f.policy == nil {
			f.policy = json.RawMessage(`{"roles":[{"name":"admin","description":"full access"},{"name":"auditor"}],"grants":[{"role":"admin","entity":"patient","action":"read"},{"role":"auditor","entity":"patient","action":"list"}]}`)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(f.policy)
	})
	return mux
}

func (f *fakeAdminServer) record(r *http.Request, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, adminCall{method: r.Method, path: r.URL.Path, body: body})
}

func (f *fakeAdminServer) callsOf(method string) []adminCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []adminCall
	for _, c := range f.requests {
		if c.method == method {
			out = append(out, c)
		}
	}
	return out
}

// setupCLITestAgainst stands up a fake admin server and primes the CLI
// token cache so the user/role verbs can address it. Returns the
// server URL the caller passes via --server.
func setupCLITestAgainst(t *testing.T, fake *fakeAdminServer) string {
	t.Helper()
	srv := httptest.NewServer(fake.handler())
	t.Cleanup(srv.Close)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cache, err := defaultTokenCache()
	if err != nil {
		t.Fatalf("defaultTokenCache: %v", err)
	}
	if err := cache.save(srv.URL, "tok"); err != nil {
		t.Fatalf("cache.save: %v", err)
	}
	return srv.URL
}

// `kura user list` GETs /api/users and renders the users with their
// roles. The empty list is reported explicitly, so an agent learns
// "no users" without grepping the body.
func TestUserListRendersUsers(t *testing.T) {
	fake := newFakeAdminServer(t)
	fake.users["alice@client.com"] = []string{"admin"}
	fake.users["bob@client.com"] = nil
	server := setupCLITestAgainst(t, fake)

	stdout, _, err := runRoot(t, "user", "list", "--server", server)
	if err != nil {
		t.Fatalf("user list: %v", err)
	}
	got := stdout.String()
	for _, want := range []string{"alice@client.com", "bob@client.com", "admin", "no roles"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

// `kura user list` with no users on the list renders an explicit empty
// message rather than an empty document.
func TestUserListEmptyStateIsExplicit(t *testing.T) {
	fake := newFakeAdminServer(t)
	server := setupCLITestAgainst(t, fake)

	stdout, _, err := runRoot(t, "user", "list", "--server", server)
	if err != nil {
		t.Fatalf("user list: %v", err)
	}
	if !strings.Contains(stdout.String(), "no users") {
		t.Errorf("empty list should say so explicitly:\n%s", stdout.String())
	}
}

// `kura user add a b c` is variadic: three positional emails fan out
// to three POST /api/users calls, and the success ack teaches the next
// step (`kura role assign`). Idempotent end-to-end — re-running adds
// nothing the second time.
func TestUserAddIsVariadicAndTeaches(t *testing.T) {
	fake := newFakeAdminServer(t)
	server := setupCLITestAgainst(t, fake)

	stdout, _, err := runRoot(t, "user", "add", "alice@client.com", "bob@client.com", "carol@client.com", "--server", server)
	if err != nil {
		t.Fatalf("user add: %v", err)
	}
	posts := fake.callsOf(http.MethodPost)
	if len(posts) != 3 {
		t.Errorf("variadic add: got %d POST calls, want 3", len(posts))
	}
	out := stdout.String()
	if !strings.Contains(out, "Added 3 user(s)") {
		t.Errorf("ack does not name the count:\n%s", out)
	}
	if !strings.Contains(out, "kura role assign") {
		t.Errorf("ack does not teach the role-assignment verb:\n%s", out)
	}

	// Re-run: idempotent. Six POSTs total, all 204; the user count
	// at the server is still 3.
	if _, _, err := runRoot(t, "user", "add", "alice@client.com", "bob@client.com", "carol@client.com", "--server", server); err != nil {
		t.Fatalf("re-add: %v", err)
	}
	if got := len(fake.users); got != 3 {
		t.Errorf("after idempotent re-add, server holds %d users, want 3", got)
	}
}

// `kura user add` with no arguments is a usage error that names the
// missing input — the agent gets the fix on the first line.
func TestUserAddRequiresAtLeastOneEmail(t *testing.T) {
	fake := newFakeAdminServer(t)
	server := setupCLITestAgainst(t, fake)
	_, _, err := runRoot(t, "user", "add", "--server", server)
	if err == nil {
		t.Fatal("expected a usage error")
	}
	if !strings.Contains(err.Error(), "email is required") {
		t.Errorf("error %q does not name the missing input", err)
	}
}

// `kura user deactivate a b` is variadic and fans out to per-user
// DELETE calls. The ack hints at `kura role assign` for restoration.
func TestUserDeactivateIsVariadic(t *testing.T) {
	fake := newFakeAdminServer(t)
	fake.users["alice@client.com"] = []string{"admin", "user"}
	fake.users["bob@client.com"] = []string{"user"}
	server := setupCLITestAgainst(t, fake)

	stdout, _, err := runRoot(t, "user", "deactivate", "alice@client.com", "bob@client.com", "--server", server)
	if err != nil {
		t.Fatalf("user deactivate: %v", err)
	}
	deletes := fake.callsOf(http.MethodDelete)
	if len(deletes) != 2 {
		t.Errorf("variadic deactivate: got %d DELETE calls, want 2", len(deletes))
	}
	if len(fake.users["alice@client.com"]) != 0 || len(fake.users["bob@client.com"]) != 0 {
		t.Errorf("deactivated users still hold roles: alice=%v bob=%v", fake.users["alice@client.com"], fake.users["bob@client.com"])
	}
	if !strings.Contains(stdout.String(), "kura role assign") {
		t.Errorf("ack does not teach the role-assignment next step:\n%s", stdout.String())
	}
}

// `kura user show` resolves one email out of the list — and reports a
// NotFound (taxonomy KindNotFound) for a missing user with a fix-hint
// pointing at `kura user list`.
func TestUserShowSingleAndNotFound(t *testing.T) {
	fake := newFakeAdminServer(t)
	fake.users["alice@client.com"] = []string{"admin"}
	server := setupCLITestAgainst(t, fake)

	stdout, _, err := runRoot(t, "user", "show", "alice@client.com", "--server", server, "--json")
	if err != nil {
		t.Fatalf("user show: %v", err)
	}
	var p struct {
		Users []struct {
			Email string   `json:"email"`
			Roles []string `json:"roles"`
		} `json:"users"`
	}
	if err := json.NewDecoder(&stdout).Decode(&p); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout.String())
	}
	if len(p.Users) != 1 || p.Users[0].Email != "alice@client.com" {
		t.Errorf("user show filtered to %+v, want only alice", p.Users)
	}

	_, _, err = runRoot(t, "user", "show", "nobody@client.com", "--server", server)
	if err == nil {
		t.Fatal("expected NotFound for missing user")
	}
	if !strings.Contains(err.Error(), "kura user list") {
		t.Errorf("error %q does not name the menu verb", err)
	}
}
