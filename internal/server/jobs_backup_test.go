package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/backup"
	"github.com/bensyverson/kura/internal/identity"
	"github.com/bensyverson/kura/internal/jobs"
	"github.com/bensyverson/kura/internal/storage"
)

// fakeDumper stands in for pg_dump/pg_restore so the async path can run
// without a real database. The real encrypt→store→decrypt round-trip is
// covered by internal/backup's integration test; here the point is the
// end-to-end async wiring: submit → worker → audit + ledger.
type fakeDumper struct{}

func (fakeDumper) Dump(_ context.Context, _ string) ([]byte, error) {
	return []byte("pg_dump output"), nil
}
func (fakeDumper) Restore(_ context.Context, _ string, _ []byte) error { return nil }

// A backup submitted over the API runs through the worker, lands its
// result on the jobs ledger, and records a backup.created audit event
// that names the authenticated principal — not whatever the client put in
// params. The restore leg does the same with backup.restored. This is the
// criteria-proving test for fvbRA: both commands audited and on the
// ledger (E7K), restore verifiable (yYc), key sourced/distinct (OSH, via
// the Service the worker runs).
func TestBackupRestoreRoundTripAuditedAndOnLedger(t *testing.T) {
	h := newJobsTestHarness(t)
	store := storage.NewFake(storage.BackupsSpec(), storage.AppendOnly)
	svc := &backup.Service{
		Dumper:   fakeDumper{},
		Store:    store,
		Key:      backup.DeriveKey("backup-secret-distinct-from-runtime"),
		Recorder: h.cfg.Recorder,
		DSN:      "postgres://test",
	}
	svc.Register(h.mgr)
	tok := h.seedActor(t, "admin@client.com", identity.PrincipalAdmin, "admin")
	base, stop := h.startListener(t)
	defer stop()

	// Backup leg. The client sends no actor — the server stamps it.
	backupJob := submitAndAwait(t, base, tok, map[string]any{
		"kind":            "backup",
		"idempotency_key": "b-1",
	})
	if backupJob.Status != jobs.StatusSucceeded {
		t.Fatalf("backup job status = %q; want succeeded (error: %s)", backupJob.Status, backupJob.Error)
	}
	var res backup.BackupResult
	if err := json.Unmarshal(backupJob.Result, &res); err != nil {
		t.Fatalf("decoding backup result from ledger: %v\n%s", err, backupJob.Result)
	}
	if res.ObjectKey == "" || res.SHA256 == "" {
		t.Errorf("backup result missing object_key/sha256 on the ledger: %+v", res)
	}

	// Audited: backup.created names the real admin, with the object key.
	created := auditEventsFor(t, h.cfg.Audit, backup.ActionBackupCreated)
	if len(created) != 1 {
		t.Fatalf("got %d backup.created events; want 1", len(created))
	}
	if created[0].Actor.Email != "admin@client.com" {
		t.Errorf("backup.created actor = %q; want admin@client.com", created[0].Actor.Email)
	}
	if created[0].Resource.ID != res.ObjectKey {
		t.Errorf("backup.created resource id = %q; want %q", created[0].Resource.ID, res.ObjectKey)
	}

	// Restore leg, against the object the backup produced.
	restoreJob := submitAndAwait(t, base, tok, map[string]any{
		"kind":            "restore",
		"idempotency_key": "r-1",
		"params":          map[string]string{"object_key": res.ObjectKey},
	})
	if restoreJob.Status != jobs.StatusSucceeded {
		t.Fatalf("restore job status = %q; want succeeded (error: %s)", restoreJob.Status, restoreJob.Error)
	}
	restored := auditEventsFor(t, h.cfg.Audit, backup.ActionBackupRestored)
	if len(restored) != 1 {
		t.Fatalf("got %d backup.restored events; want 1", len(restored))
	}
	if restored[0].Actor.Email != "admin@client.com" {
		t.Errorf("backup.restored actor = %q; want admin@client.com", restored[0].Actor.Email)
	}
	if restored[0].Resource.ID != res.ObjectKey {
		t.Errorf("backup.restored resource id = %q; want %q", restored[0].Resource.ID, res.ObjectKey)
	}
}

// submitAndAwait POSTs a job as the given token and polls GET
// /api/jobs/{id} until the job is terminal, returning the final job.
func submitAndAwait(t *testing.T, base, tok string, body map[string]any) jobs.Job {
	t.Helper()
	raw, _ := json.Marshal(body)
	resp, err := postJSON(base+"/api/jobs", tok, raw)
	if err != nil {
		t.Fatalf("POST /api/jobs: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST status = %d, body = %s", resp.StatusCode, mustString(resp.Body))
	}
	var submitted struct {
		Job jobs.Job `json:"job"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&submitted); err != nil {
		t.Fatalf("decode submit: %v", err)
	}
	resp.Body.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		getResp, err := getWithToken(base+"/api/jobs/"+submitted.Job.ID, tok)
		if err != nil {
			t.Fatalf("GET job: %v", err)
		}
		var got jobs.Job
		if err := json.NewDecoder(getResp.Body).Decode(&got); err != nil {
			getResp.Body.Close()
			t.Fatalf("decode job: %v", err)
		}
		getResp.Body.Close()
		if got.Status.Terminal() {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("job %s did not reach terminal within 2s", submitted.Job.ID)
	return jobs.Job{}
}

// auditEventsFor queries the audit store for events with the given action.
func auditEventsFor(t *testing.T, store audit.Store, action string) []audit.Event {
	t.Helper()
	events, err := store.Query(context.Background(), audit.Filter{Action: action})
	if err != nil {
		t.Fatalf("audit query: %v", err)
	}
	return events
}
