package jobs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrMissingDependency is returned by NewPostgresStore when a required
// collaborator is missing. A store that cannot read or write safely —
// no pool, or no tenant to scope RLS to — must not come into existence.
var ErrMissingDependency = errors.New("jobs: postgres store is missing a required dependency")

// PostgresStore is the production Store: it reads and writes the
// kura.jobs table. Every operation runs inside a tenant-scoped
// transaction, so the row-level-security policy from migration 0005
// binds — a store scoped to one tenant can neither see nor write
// another tenant's jobs.
//
// The store is also where the ledger's two cardinal properties land:
//
//   - Idempotency. Submit uses ON CONFLICT against the unique key
//     (tenant_id, actor, kind, idempotency_key) to either insert or
//     return the existing row. A retry through a fresh process finds
//     the same job.
//
//   - Crash recovery. ResetOrphans flips any row left in 'running'
//     back to 'pending', so a worker that died mid-job is picked up
//     exactly once by the next worker.
type PostgresStore struct {
	db       *sql.DB
	tenantID string
}

var _ Store = (*PostgresStore)(nil)

// NewPostgresStore returns a PostgresStore over db, scoped to tenantID.
// The pool should be connected as the RLS-bound kura_api role.
func NewPostgresStore(db *sql.DB, tenantID string) (*PostgresStore, error) {
	if db == nil || tenantID == "" {
		return nil, ErrMissingDependency
	}
	return &PostgresStore{db: db, tenantID: tenantID}, nil
}

// Submit inserts j or returns the existing job for the same (tenant,
// actor, kind, idempotency_key). The whole decision happens in one SQL
// statement: an ON-CONFLICT INSERT that returns the new id on conflict
// or the inserted one otherwise, plus a flag telling us which.
func (s *PostgresStore) Submit(ctx context.Context, j Job) (Job, bool, error) {
	var (
		out     Job
		created bool
	)
	err := s.tx(ctx, false, func(tx *sql.Tx) error {
		// Try to insert. ON CONFLICT DO NOTHING returns no rows on a
		// conflict; we then look the existing row up by the key.
		var rowID string
		err := tx.QueryRowContext(ctx, `
			INSERT INTO kura.jobs
				(id, tenant_id, kind, status, actor, idempotency_key, params, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, COALESCE($7::jsonb, '{}'::jsonb), $8)
			ON CONFLICT (tenant_id, actor, kind, idempotency_key) DO NOTHING
			RETURNING id`,
			j.ID, s.tenantID, j.Kind, string(j.Status), j.Actor, j.IdempotencyKey,
			rawOrNull(j.Params), j.CreatedAt).Scan(&rowID)
		if errors.Is(err, sql.ErrNoRows) {
			// Conflict: read the existing row.
			existing, getErr := getJobLocked(ctx, tx, j.Actor, j.Kind, j.IdempotencyKey)
			if getErr != nil {
				return getErr
			}
			out = existing
			created = false
			return nil
		}
		if err != nil {
			return err
		}
		// Fresh insert: read back so callers see normalized timestamps.
		fresh, getErr := getJobByID(ctx, tx, rowID)
		if getErr != nil {
			return getErr
		}
		out = fresh
		created = true
		return nil
	})
	if err != nil {
		return Job{}, false, err
	}
	return out, created, nil
}

// Get returns the actor's job by id, or ErrJobNotFound. RLS already
// scopes visibility to the tenant; the actor filter scopes within it.
func (s *PostgresStore) Get(ctx context.Context, actor, id string) (Job, error) {
	var out Job
	err := s.tx(ctx, true, func(tx *sql.Tx) error {
		j, err := getJobByID(ctx, tx, id)
		if err != nil {
			return err
		}
		if j.Actor != actor {
			return ErrJobNotFound
		}
		out = j
		return nil
	})
	if err != nil {
		return Job{}, err
	}
	return out, nil
}

// List returns the actor's jobs newest first.
func (s *PostgresStore) List(ctx context.Context, actor string) ([]Job, error) {
	var out []Job
	err := s.tx(ctx, true, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, jobsSelectColumns+`
			FROM kura.jobs WHERE actor = $1
			ORDER BY created_at DESC, id`,
			actor)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			j, err := scanJob(rows)
			if err != nil {
				return err
			}
			out = append(out, j)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ClaimNextPending atomically transitions one pending job to running.
// SELECT ... FOR UPDATE SKIP LOCKED is the standard worker pattern: two
// workers polling at once each get their own row, neither blocks on the
// other.
func (s *PostgresStore) ClaimNextPending(ctx context.Context) (Job, bool, error) {
	var (
		out   Job
		found bool
	)
	err := s.tx(ctx, false, func(tx *sql.Tx) error {
		var id string
		err := tx.QueryRowContext(ctx, `
			SELECT id FROM kura.jobs
			WHERE status = 'pending'
			ORDER BY created_at, id
			LIMIT 1
			FOR UPDATE SKIP LOCKED`).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		if _, err := tx.ExecContext(ctx, `
			UPDATE kura.jobs SET status = 'running', started_at = $2 WHERE id = $1`,
			id, now); err != nil {
			return err
		}
		j, err := getJobByID(ctx, tx, id)
		if err != nil {
			return err
		}
		out = j
		found = true
		return nil
	})
	if err != nil {
		return Job{}, false, err
	}
	return out, found, nil
}

// MarkSucceeded transitions a running job to succeeded.
func (s *PostgresStore) MarkSucceeded(ctx context.Context, id string, result json.RawMessage) error {
	return s.tx(ctx, false, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE kura.jobs
			SET status = 'succeeded', result = $2::jsonb, error = '', finished_at = $3
			WHERE id = $1`,
			id, rawOrNull(result), time.Now().UTC())
		if err != nil {
			return err
		}
		return ensureOneRow(res, "MarkSucceeded", id)
	})
}

// MarkFailed transitions a running job to failed.
func (s *PostgresStore) MarkFailed(ctx context.Context, id string, errMsg string) error {
	return s.tx(ctx, false, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE kura.jobs
			SET status = 'failed', error = $2, finished_at = $3
			WHERE id = $1`,
			id, errMsg, time.Now().UTC())
		if err != nil {
			return err
		}
		return ensureOneRow(res, "MarkFailed", id)
	})
}

// ResetOrphans flips every running job back to pending. Crash recovery
// at startup: a worker that died mid-job leaves a 'running' row with no
// finished_at; the next worker picks it up exactly once.
func (s *PostgresStore) ResetOrphans(ctx context.Context) error {
	return s.tx(ctx, false, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			UPDATE kura.jobs SET status = 'pending', started_at = NULL
			WHERE status = 'running'`)
		return err
	})
}

// jobsSelectColumns names the columns scanJob reads, in order. Kept in
// one constant so SELECT and scan stay in sync.
const jobsSelectColumns = `SELECT id, kind, status, actor, idempotency_key,
	COALESCE(params::text, '{}'), COALESCE(result::text, ''),
	error, created_at, started_at, finished_at`

// scanJob reads one row from a rows or row produced by jobsSelectColumns.
func scanJob(scanner interface {
	Scan(dest ...any) error
}) (Job, error) {
	var (
		j          Job
		paramsStr  string
		resultStr  string
		startedAt  sql.NullTime
		finishedAt sql.NullTime
		status     string
	)
	if err := scanner.Scan(&j.ID, &j.Kind, &status, &j.Actor, &j.IdempotencyKey,
		&paramsStr, &resultStr, &j.Error, &j.CreatedAt, &startedAt, &finishedAt); err != nil {
		return Job{}, err
	}
	j.Status = Status(status)
	if paramsStr != "" {
		j.Params = json.RawMessage(paramsStr)
	}
	if resultStr != "" {
		j.Result = json.RawMessage(resultStr)
	}
	if startedAt.Valid {
		t := startedAt.Time
		j.StartedAt = &t
	}
	if finishedAt.Valid {
		t := finishedAt.Time
		j.FinishedAt = &t
	}
	return j, nil
}

// getJobByID reads one job by id within the open transaction. RLS has
// already scoped visibility to the tenant.
func getJobByID(ctx context.Context, tx *sql.Tx, id string) (Job, error) {
	row := tx.QueryRowContext(ctx, jobsSelectColumns+` FROM kura.jobs WHERE id = $1`, id)
	j, err := scanJob(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Job{}, ErrJobNotFound
	}
	return j, err
}

// getJobLocked reads one job by its idempotency key. Used inside Submit
// to look up the existing row on a conflict.
func getJobLocked(ctx context.Context, tx *sql.Tx, actor, kind, key string) (Job, error) {
	row := tx.QueryRowContext(ctx,
		jobsSelectColumns+` FROM kura.jobs WHERE actor = $1 AND kind = $2 AND idempotency_key = $3`,
		actor, kind, key)
	j, err := scanJob(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Job{}, ErrJobNotFound
	}
	return j, err
}

// ensureOneRow turns a 0-row UPDATE into ErrJobNotFound. A transition
// targeting a missing id is a programming error, not a silent no-op.
func ensureOneRow(res sql.Result, op, id string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("jobs: %s: %w (id=%s)", op, ErrJobNotFound, id)
	}
	return nil
}

// rawOrNull turns a nil or empty RawMessage into nil so the placeholder
// receives SQL NULL rather than the literal string "null".
func rawOrNull(r json.RawMessage) any {
	if len(r) == 0 {
		return nil
	}
	return string(r)
}

// tx runs fn inside a tenant-scoped transaction. set_config's third
// argument is true — transaction-local — so the kura.tenant_id GUC
// cannot leak onto a later use of this pooled connection. RLS reads
// that GUC, so without it the transaction sees nothing.
func (s *PostgresStore) tx(ctx context.Context, readOnly bool, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: readOnly})
	if err != nil {
		return fmt.Errorf("jobs: begin tx: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx,
		`SELECT set_config('kura.tenant_id', $1, true)`, s.tenantID); err != nil {
		return fmt.Errorf("jobs: setting tenant scope: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}
