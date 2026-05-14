package data

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/bensyverson/kura/internal/identity"
)

// PostgresUserStore is the production UserStore over the kura.users and
// kura.role_assignments tables. Like PostgresStore it runs every
// operation inside a tenant-scoped transaction, so the row-level-security
// policies bind: a store scoped to one tenant can neither see nor mutate
// another's authorized list. Reads use a read-only transaction; the
// variadic role mutations run as one read-write transaction, which is
// what makes them atomic.
type PostgresUserStore struct {
	db       *sql.DB
	tenantID string
}

var _ UserStore = (*PostgresUserStore)(nil)

// NewPostgresUserStore returns a PostgresUserStore over db, scoped to
// tenantID. The pool should be connected as the RLS-bound kura_api role.
func NewPostgresUserStore(db *sql.DB, tenantID string) (*PostgresUserStore, error) {
	if db == nil || tenantID == "" {
		return nil, ErrMissingDependency
	}
	return &PostgresUserStore{db: db, tenantID: tenantID}, nil
}

// AddUser adds email to the authorized list, idempotently. The explicit
// tenant_id matches the GUC the transaction sets, so the RLS WITH CHECK
// is satisfied.
func (s *PostgresUserStore) AddUser(ctx context.Context, email string) error {
	email = strings.ToLower(email)
	return withTenantTx(ctx, s.db, s.tenantID, false, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO kura.users (tenant_id, email) VALUES ($1, $2)
			 ON CONFLICT (tenant_id, email) DO NOTHING`,
			s.tenantID, email)
		return err
	})
}

// ListUsers returns the authorized list in email order, each user with
// its roles. The LEFT JOIN keeps users who hold no roles.
func (s *PostgresUserStore) ListUsers(ctx context.Context) ([]User, error) {
	var users []User
	err := withTenantTx(ctx, s.db, s.tenantID, true, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx,
			`SELECT u.email, ra.role
			 FROM kura.users u
			 LEFT JOIN kura.role_assignments ra ON ra.user_id = u.id
			 ORDER BY u.email, ra.role`)
		if err != nil {
			return err
		}
		defer rows.Close()

		byEmail := make(map[string]int) // email -> index in users
		for rows.Next() {
			var email string
			var role sql.NullString
			if err := rows.Scan(&email, &role); err != nil {
				return err
			}
			idx, ok := byEmail[email]
			if !ok {
				idx = len(users)
				byEmail[email] = idx
				users = append(users, User{Email: email})
			}
			if role.Valid {
				users[idx].Roles = append(users[idx].Roles, role.String)
			}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return users, nil
}

// AssignRoles grants roles to email. The whole set is applied in one
// transaction, so it is atomic; each insert is idempotent.
func (s *PostgresUserStore) AssignRoles(ctx context.Context, email string, roles ...string) error {
	email = strings.ToLower(email)
	return withTenantTx(ctx, s.db, s.tenantID, false, func(tx *sql.Tx) error {
		userID, err := userIDByEmail(ctx, tx, email)
		if err != nil {
			return err
		}
		for _, role := range roles {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO kura.role_assignments (user_id, tenant_id, role) VALUES ($1, $2, $3)
				 ON CONFLICT (user_id, role) DO NOTHING`,
				userID, s.tenantID, role); err != nil {
				return err
			}
		}
		return nil
	})
}

// RevokeRoles removes roles from email, in one atomic transaction.
// Revoking a role the user does not hold deletes nothing — a no-op.
func (s *PostgresUserStore) RevokeRoles(ctx context.Context, email string, roles ...string) error {
	email = strings.ToLower(email)
	return withTenantTx(ctx, s.db, s.tenantID, false, func(tx *sql.Tx) error {
		userID, err := userIDByEmail(ctx, tx, email)
		if err != nil {
			return err
		}
		for _, role := range roles {
			if _, err := tx.ExecContext(ctx,
				`DELETE FROM kura.role_assignments WHERE user_id = $1 AND role = $2`,
				userID, role); err != nil {
				return err
			}
		}
		return nil
	})
}

// Roles resolves principal to its role names. A principal not on the
// authorized list resolves to no roles — not an error.
func (s *PostgresUserStore) Roles(ctx context.Context, principal identity.Principal) ([]string, error) {
	email := strings.ToLower(principal.ID)
	var roles []string
	err := withTenantTx(ctx, s.db, s.tenantID, true, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx,
			`SELECT ra.role
			 FROM kura.users u
			 JOIN kura.role_assignments ra ON ra.user_id = u.id
			 WHERE u.email = $1
			 ORDER BY ra.role`,
			email)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var role string
			if err := rows.Scan(&role); err != nil {
				return err
			}
			roles = append(roles, role)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return roles, nil
}

// userIDByEmail returns the id of the authorized user with the given
// email. A missing user is ErrUserNotFound — the caller (AssignRoles /
// RevokeRoles) turns that into the documented error rather than silently
// doing nothing. RLS has already scoped the lookup to the tenant.
func userIDByEmail(ctx context.Context, tx *sql.Tx, email string) (string, error) {
	var id string
	err := tx.QueryRowContext(ctx, `SELECT id::text FROM kura.users WHERE email = $1`, email).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrUserNotFound
	}
	if err != nil {
		return "", err
	}
	return id, nil
}
