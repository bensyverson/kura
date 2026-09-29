package db

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"
)

// TestRecordSequenceAssignedMonotonically covers the record-ordering
// criterion (substrate Item F): every record is assigned a non-null bigint
// seq from one shared sequence at INSERT, strictly increasing, so "events
// for a subject, ordered" has a deterministic, clock-skew-immune order key.
// created_at is retained for wall-clock meaning but is not the order key.
func TestRecordSequenceAssignedMonotonically(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	if err := Migrate(ctx, env.DB); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	tenant := newUUID(ctx, t, env.DB)
	conn := tenantConn(ctx, t, env.DB, tenant)

	// Each insert draws the next value from the shared sequence and still
	// populates created_at. Successive inserts must strictly increase.
	var prevSeq int64
	for i := range 3 {
		var seq int64
		var createdAt time.Time
		if err := conn.QueryRowContext(ctx,
			`INSERT INTO kura.records (tenant_id, entity) VALUES ($1, 'client')
			 RETURNING seq, created_at`, tenant).Scan(&seq, &createdAt); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
		if seq <= 0 {
			t.Fatalf("insert %d: seq = %d, want > 0", i, seq)
		}
		if i > 0 && seq <= prevSeq {
			t.Fatalf("insert %d: seq = %d not greater than previous %d", i, seq, prevSeq)
		}
		if createdAt.IsZero() {
			t.Fatalf("insert %d: created_at is zero, want it retained", i)
		}
		prevSeq = seq
	}

	// The column itself is a NOT NULL bigint backed by a sequence default,
	// so the order key can never be absent and is server-assigned.
	var dataType, isNullable string
	var columnDefault sql.NullString
	if err := env.DB.QueryRowContext(ctx,
		`SELECT data_type, is_nullable, column_default
		   FROM information_schema.columns
		  WHERE table_schema = 'kura' AND table_name = 'records' AND column_name = 'seq'`).
		Scan(&dataType, &isNullable, &columnDefault); err != nil {
		t.Fatalf("reading seq column metadata: %v", err)
	}
	if dataType != "bigint" {
		t.Errorf("seq data_type = %q, want bigint", dataType)
	}
	if isNullable != "NO" {
		t.Errorf("seq is_nullable = %q, want NO", isNullable)
	}
	if !columnDefault.Valid || !strings.Contains(columnDefault.String, "nextval") {
		t.Errorf("seq column_default = %v, want a nextval(...) sequence default", columnDefault)
	}
}
