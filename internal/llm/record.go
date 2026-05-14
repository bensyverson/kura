package llm

import (
	"context"
	"sync"
	"time"

	"github.com/bensyverson/kura/internal/identity"
)

// CallRecord is the metadata-only audit record of one LLM call. Like
// audit.Event, it is structurally incapable of carrying data contents:
// it has no field for the prompt or the response, only their SHA-256
// hashes. A hash is a fingerprint, not the content — it lets an auditor
// correlate or detect tampering without the log ever holding what was
// sent to the provider.
type CallRecord struct {
	Time         time.Time
	Principal    identity.Principal
	Model        string
	InputTokens  int
	OutputTokens int
	// PromptHash and ResponseHash are SHA-256 hex digests of the prompt
	// and response content.
	PromptHash   string
	ResponseHash string
}

// MetadataLog is the append-only sink for CallRecords — the audit log of
// LLM calls. It is separate from internal/audit because an LLM call is a
// different kind of event with different metadata; the contents-never
// guarantee is the same.
type MetadataLog interface {
	// Record durably appends one call record.
	Record(ctx context.Context, rec CallRecord) error
}

// MemLog is an in-memory MetadataLog for tests and for break-glass paths
// that run before a durable log is reachable.
type MemLog struct {
	mu      sync.Mutex
	records []CallRecord
}

// NewMemLog returns an empty in-memory MetadataLog.
func NewMemLog() *MemLog {
	return &MemLog{}
}

// Record appends rec.
func (l *MemLog) Record(_ context.Context, rec CallRecord) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.records = append(l.records, rec)
	return nil
}

// Records returns a copy of the recorded call records, in append order.
func (l *MemLog) Records() []CallRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]CallRecord, len(l.records))
	copy(out, l.records)
	return out
}
