package review

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// PostgresStore is the production Store over the kura.access_reviews and
// kura.access_review_items tables. Like the other Postgres stores it runs
// every operation inside a tenant-scoped transaction, so the row-level
// security policies bind: a store scoped to one tenant can neither see nor
// mutate another's reviews. Reads use a read-only transaction; a create or
// a decision runs as one read-write transaction, which is what makes the
// header-plus-items write atomic.
type PostgresStore struct {
	db       *sql.DB
	tenantID string
	now      func() time.Time
}

var _ Store = (*PostgresStore)(nil)

// NewPostgresStore returns a PostgresStore over db, scoped to tenantID. The
// pool should be connected as the RLS-bound kura_api role.
func NewPostgresStore(db *sql.DB, tenantID string) (*PostgresStore, error) {
	if db == nil || tenantID == "" {
		return nil, ErrMissingDependency
	}
	return &PostgresStore{db: db, tenantID: tenantID, now: time.Now}, nil
}

// Create persists a new open review and its snapshot items in one atomic
// transaction.
func (s *PostgresStore) Create(ctx context.Context, startedBy string, subjects []Item) (Review, error) {
	if len(subjects) == 0 {
		return Review{}, ErrEmptyReview
	}
	id, err := newReviewID()
	if err != nil {
		return Review{}, err
	}
	var r Review
	err = withTenantTx(ctx, s.db, s.tenantID, false, func(tx *sql.Tx) error {
		var startedAt time.Time
		if err := tx.QueryRowContext(ctx,
			`INSERT INTO kura.access_reviews (id, tenant_id, started_by, status)
			 VALUES ($1, $2, $3, 'open') RETURNING started_at`,
			id, s.tenantID, startedBy).Scan(&startedAt); err != nil {
			return err
		}
		items := make([]Item, len(subjects))
		for i, sub := range subjects {
			email := strings.ToLower(sub.Email)
			roles := sub.RolesAtReview
			if roles == nil {
				roles = []string{}
			}
			rolesJSON, err := json.Marshal(roles)
			if err != nil {
				return fmt.Errorf("review: encoding roles: %w", err)
			}
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO kura.access_review_items (review_id, tenant_id, email, roles, decision)
				 VALUES ($1, $2, $3, $4::jsonb, 'pending')`,
				id, s.tenantID, email, string(rolesJSON)); err != nil {
				return err
			}
			items[i] = Item{Email: email, RolesAtReview: append([]string(nil), roles...), Decision: DecisionPending}
		}
		r = Review{ID: id, StartedAt: startedAt, StartedBy: startedBy, Status: StatusOpen, Items: items}
		return nil
	})
	if err != nil {
		return Review{}, err
	}
	return r, nil
}

// Get returns the review with id and its items.
func (s *PostgresStore) Get(ctx context.Context, id string) (Review, error) {
	var r Review
	err := withTenantTx(ctx, s.db, s.tenantID, true, func(tx *sql.Tx) error {
		var err error
		r, err = readReview(ctx, tx, id)
		return err
	})
	if err != nil {
		return Review{}, err
	}
	return r, nil
}

// List returns reviews newest-first, each with its items.
func (s *PostgresStore) List(ctx context.Context) ([]Review, error) {
	var out []Review
	err := withTenantTx(ctx, s.db, s.tenantID, true, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx,
			`SELECT id, started_by, status, started_at, completed_at
			 FROM kura.access_reviews ORDER BY started_at DESC, id DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		byID := make(map[string]int)
		for rows.Next() {
			r, err := scanReviewHeader(rows)
			if err != nil {
				return err
			}
			byID[r.ID] = len(out)
			out = append(out, r)
		}
		if err := rows.Err(); err != nil {
			return err
		}

		itemRows, err := tx.QueryContext(ctx,
			`SELECT review_id, email, roles::text, decision, note
			 FROM kura.access_review_items ORDER BY email`)
		if err != nil {
			return err
		}
		defer itemRows.Close()
		for itemRows.Next() {
			var reviewID string
			it, err := scanItem(itemRows, &reviewID)
			if err != nil {
				return err
			}
			if idx, ok := byID[reviewID]; ok {
				out[idx].Items = append(out[idx].Items, it)
			}
		}
		return itemRows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Decide records decision and note for email in an open review.
func (s *PostgresStore) Decide(ctx context.Context, id, email string, decision Decision, note string) error {
	if !decision.recordable() {
		return ErrInvalidDecision
	}
	email = strings.ToLower(email)
	return withTenantTx(ctx, s.db, s.tenantID, false, func(tx *sql.Tx) error {
		if err := assertOpen(ctx, tx, id); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx,
			`UPDATE kura.access_review_items SET decision = $3, note = $4
			 WHERE review_id = $1 AND email = $2`,
			id, email, string(decision), note)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrSubjectNotFound
		}
		return nil
	})
}

// Complete marks an open review completed and returns the artifact.
func (s *PostgresStore) Complete(ctx context.Context, id string) (Review, error) {
	var r Review
	err := withTenantTx(ctx, s.db, s.tenantID, false, func(tx *sql.Tx) error {
		if err := assertOpen(ctx, tx, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE kura.access_reviews SET status = 'completed', completed_at = now() WHERE id = $1`,
			id); err != nil {
			return err
		}
		var err error
		r, err = readReview(ctx, tx, id)
		return err
	})
	if err != nil {
		return Review{}, err
	}
	return r, nil
}

// assertOpen returns ErrNotFound if id does not exist, ErrClosed if it is
// already completed, or nil if it is open.
func assertOpen(ctx context.Context, tx *sql.Tx, id string) error {
	var status string
	err := tx.QueryRowContext(ctx, `SELECT status FROM kura.access_reviews WHERE id = $1`, id).Scan(&status)
	if err == sql.ErrNoRows {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if status == string(StatusCompleted) {
		return ErrClosed
	}
	return nil
}

// readReview reads one review header and its items within tx.
func readReview(ctx context.Context, tx *sql.Tx, id string) (Review, error) {
	row := tx.QueryRowContext(ctx,
		`SELECT id, started_by, status, started_at, completed_at
		 FROM kura.access_reviews WHERE id = $1`, id)
	r, err := scanReviewHeader(row)
	if err == sql.ErrNoRows {
		return Review{}, ErrNotFound
	}
	if err != nil {
		return Review{}, err
	}
	rows, err := tx.QueryContext(ctx,
		`SELECT review_id, email, roles::text, decision, note
		 FROM kura.access_review_items WHERE review_id = $1 ORDER BY email`, id)
	if err != nil {
		return Review{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var reviewID string
		it, err := scanItem(rows, &reviewID)
		if err != nil {
			return Review{}, err
		}
		r.Items = append(r.Items, it)
	}
	return r, rows.Err()
}

// rowScanner is the shared interface of *sql.Row and *sql.Rows, so the scan
// helpers serve both the single-row reads and the list reads.
type rowScanner interface {
	Scan(dest ...any) error
}

// scanReviewHeader scans a review header row.
func scanReviewHeader(row rowScanner) (Review, error) {
	var r Review
	var status string
	var completedAt sql.NullTime
	if err := row.Scan(&r.ID, &r.StartedBy, &status, &r.StartedAt, &completedAt); err != nil {
		return Review{}, err
	}
	r.Status = Status(status)
	if completedAt.Valid {
		t := completedAt.Time
		r.CompletedAt = &t
	}
	return r, nil
}

// scanItem scans one item row, writing the owning review id into reviewID.
func scanItem(row rowScanner, reviewID *string) (Item, error) {
	var it Item
	var rolesJSON string
	var decision string
	if err := row.Scan(reviewID, &it.Email, &rolesJSON, &decision, &it.Note); err != nil {
		return Item{}, err
	}
	it.Decision = Decision(decision)
	if err := json.Unmarshal([]byte(rolesJSON), &it.RolesAtReview); err != nil {
		return Item{}, fmt.Errorf("review: decoding roles: %w", err)
	}
	return it, nil
}

// withTenantTx runs fn inside a transaction with the tenant GUC set, so the
// RLS policies on the review tables bind. It mirrors the data package's
// helper; the review subsystem owns its own copy rather than reaching
// across package boundaries for an unexported helper.
func withTenantTx(ctx context.Context, db *sql.DB, tenantID string, readOnly bool, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: readOnly})
	if err != nil {
		return fmt.Errorf("review: begin transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `SELECT set_config('kura.tenant_id', $1, true)`, tenantID); err != nil {
		return fmt.Errorf("review: setting tenant scope: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}
