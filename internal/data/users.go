package data

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"

	"github.com/bensyverson/kura/internal/identity"
)

// ErrUserNotFound is returned by AssignRoles and RevokeRoles when the
// email is not on the authorized list. Adding a user to the list and
// granting them roles are deliberately distinct operations — you cannot
// grant a role to someone the deployment has not first authorized.
var ErrUserNotFound = errors.New("data: user not on the authorized list")

// User is one entry in the authorized-user list: an email and the role
// names it holds. A user with no roles is on the list but has no access.
type User struct {
	Email string   `json:"email"`
	Roles []string `json:"roles"`
}

// UserStore is the authorized-user list and its role assignments. It
// also satisfies the gate's RoleResolver — Roles resolves a principal to
// its role names — so the same store both *manages* access and *is* the
// source the gate consults when enforcing it: there is one list, not a
// management copy and an enforcement copy that could drift.
type UserStore interface {
	// AddUser adds email to the authorized list. Idempotent: adding an
	// already-listed user is a no-op and leaves their roles untouched.
	AddUser(ctx context.Context, email string) error
	// ListUsers returns the authorized list, each user with its roles,
	// in a stable order.
	ListUsers(ctx context.Context) ([]User, error)
	// AssignRoles grants roles to email — variadic, atomic, idempotent.
	// The user must already be on the authorized list, else
	// ErrUserNotFound.
	AssignRoles(ctx context.Context, email string, roles ...string) error
	// RevokeRoles removes roles from email — variadic, atomic. Revoking
	// a role the user does not hold is a no-op; the user must be on the
	// authorized list, else ErrUserNotFound.
	RevokeRoles(ctx context.Context, email string, roles ...string) error
	// Roles resolves principal to the role names it holds, satisfying
	// gate.RoleResolver. A principal not on the list has no roles — not
	// an error, just no access.
	Roles(ctx context.Context, principal identity.Principal) ([]string, error)
}

// IdPMismatch is an authorized user whose identity-provider account no
// longer matches their Kura access: they still hold roles, but their
// Workspace account is suspended or absent.
type IdPMismatch struct {
	Email  string                 `json:"email"`
	Roles  []string               `json:"roles"`
	Status identity.AccountStatus `json:"status"`
}

// DetectIdPMismatches cross-checks the authorized-user list against the
// identity provider. A user who holds roles but whose IdP account is not
// active — suspended or absent — is a mismatch: access the deployment no
// longer intends to grant. A user with no roles is never a mismatch,
// because there is no access to revoke.
func DetectIdPMismatches(ctx context.Context, store UserStore, dir identity.Directory) ([]IdPMismatch, error) {
	users, err := store.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	var mismatches []IdPMismatch
	for _, u := range users {
		if len(u.Roles) == 0 {
			continue
		}
		status, err := dir.AccountStatus(ctx, u.Email)
		if err != nil {
			return nil, err
		}
		if status != identity.AccountActive {
			mismatches = append(mismatches, IdPMismatch{Email: u.Email, Roles: u.Roles, Status: status})
		}
	}
	return mismatches, nil
}

// MemUserStore is an in-memory UserStore for tests and database-less
// adapters. Operations are serialized under a mutex, so the variadic
// role mutations are naturally atomic.
type MemUserStore struct {
	mu    sync.RWMutex
	roles map[string][]string // email -> roles; key present == on the list
}

var _ UserStore = (*MemUserStore)(nil)

// NewMemUserStore returns an empty MemUserStore.
func NewMemUserStore() *MemUserStore {
	return &MemUserStore{roles: make(map[string][]string)}
}

// AddUser adds email to the authorized list, idempotently.
func (s *MemUserStore) AddUser(_ context.Context, email string) error {
	email = strings.ToLower(email)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.roles[email]; !ok {
		s.roles[email] = nil
	}
	return nil
}

// ListUsers returns the authorized list in email order.
func (s *MemUserStore) ListUsers(_ context.Context) ([]User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	emails := make([]string, 0, len(s.roles))
	for e := range s.roles {
		emails = append(emails, e)
	}
	slices.Sort(emails)
	users := make([]User, len(emails))
	for i, e := range emails {
		users[i] = User{Email: e, Roles: append([]string(nil), s.roles[e]...)}
	}
	return users, nil
}

// AssignRoles grants roles to email.
func (s *MemUserStore) AssignRoles(_ context.Context, email string, roles ...string) error {
	email = strings.ToLower(email)
	s.mu.Lock()
	defer s.mu.Unlock()
	held, ok := s.roles[email]
	if !ok {
		return ErrUserNotFound
	}
	for _, r := range roles {
		if !slices.Contains(held, r) {
			held = append(held, r)
		}
	}
	slices.Sort(held)
	s.roles[email] = held
	return nil
}

// RevokeRoles removes roles from email.
func (s *MemUserStore) RevokeRoles(_ context.Context, email string, roles ...string) error {
	email = strings.ToLower(email)
	s.mu.Lock()
	defer s.mu.Unlock()
	held, ok := s.roles[email]
	if !ok {
		return ErrUserNotFound
	}
	kept := held[:0:0]
	for _, r := range held {
		if !slices.Contains(roles, r) {
			kept = append(kept, r)
		}
	}
	s.roles[email] = kept
	return nil
}

// Roles resolves principal to its role names.
func (s *MemUserStore) Roles(_ context.Context, principal identity.Principal) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.roles[strings.ToLower(principal.ID)]...), nil
}
