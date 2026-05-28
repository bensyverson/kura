package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bensyverson/kura/internal/jobs"
)

// `kura backup` is wired as a real command carrying --wait, not the
// not-implemented stub.
func TestBackupCommandIsWired(t *testing.T) {
	root := newRootCmd()
	cmd, _, err := root.Find([]string{"backup"})
	if err != nil {
		t.Fatalf("finding backup command: %v", err)
	}
	if cmd.Name() != "backup" {
		t.Fatalf("found command %q, want backup", cmd.Name())
	}
	if cmd.Flags().Lookup("wait") == nil {
		t.Error("backup command has no --wait flag")
	}
	if cmd.Flags().Lookup("idempotency-key") == nil {
		t.Error("backup command has no --idempotency-key flag")
	}
}

// `kura backup` submits a job of kind "backup" with a non-empty
// idempotency key and reports the new job id.
func TestBackupSubmitsBackupJob(t *testing.T) {
	fake := newFakeJobsServer(t)
	server := setupJobsCLITest(t, fake)

	stdout, _, err := runRoot(t, "backup", "--server", server)
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	subs := fake.submissions()
	if len(subs) != 1 {
		t.Fatalf("server received %d submissions, want 1", len(subs))
	}
	if subs[0].kind != "backup" {
		t.Errorf("submitted kind = %q, want backup", subs[0].kind)
	}
	if subs[0].key == "" {
		t.Error("submitted with an empty idempotency key")
	}
	if !strings.Contains(stdout.String(), "job-1") {
		t.Errorf("output %q does not report the job id", stdout.String())
	}
}

// An explicit --idempotency-key is sent verbatim, so an agent can
// re-attach to an in-flight backup.
func TestBackupHonorsExplicitIdempotencyKey(t *testing.T) {
	fake := newFakeJobsServer(t)
	server := setupJobsCLITest(t, fake)

	if _, _, err := runRoot(t, "backup", "--idempotency-key", "my-key", "--server", server); err != nil {
		t.Fatalf("backup: %v", err)
	}
	if subs := fake.submissions(); len(subs) != 1 || subs[0].key != "my-key" {
		t.Fatalf("submissions = %+v, want one with key my-key", subs)
	}
}

// With --wait, backup polls until the job reaches a terminal status and
// renders the backup result.
func TestBackupWaitPollsUntilTerminal(t *testing.T) {
	fake := newFakeJobsServer(t)
	fake.script = []map[string]any{
		{"id": "job-1", "kind": "backup", "status": "pending", "actor": "a@b", "idempotency_key": "k", "created_at": "2026-05-18T10:00:00Z"},
		{"id": "job-1", "kind": "backup", "status": "running", "actor": "a@b", "idempotency_key": "k", "created_at": "2026-05-18T10:00:00Z"},
		{"id": "job-1", "kind": "backup", "status": "succeeded", "actor": "a@b", "idempotency_key": "k", "created_at": "2026-05-18T10:00:00Z",
			"result": json.RawMessage(`{"object_key":"backup-x.dump.enc","bytes":1024,"sha256":"abc"}`)},
	}
	server := setupJobsCLITest(t, fake)

	prev := jobsPollInterval
	jobsPollInterval = 5 * time.Millisecond
	defer func() { jobsPollInterval = prev }()

	stdout, _, err := runRoot(t, "backup", "--wait", "--timeout", "2s", "--server", server)
	if err != nil {
		t.Fatalf("backup --wait: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, string(jobs.StatusSucceeded)) {
		t.Errorf("output %q does not show the terminal status", out)
	}
	if !strings.Contains(out, "backup-x.dump.enc") {
		t.Errorf("output %q does not show the backup object key", out)
	}
}

// --json emits the job as JSON.
func TestBackupJSONOutput(t *testing.T) {
	fake := newFakeJobsServer(t)
	server := setupJobsCLITest(t, fake)

	stdout, _, err := runRoot(t, "backup", "--json", "--server", server)
	if err != nil {
		t.Fatalf("backup --json: %v", err)
	}
	var j jobs.Job
	if err := json.Unmarshal(stdout.Bytes(), &j); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, stdout.String())
	}
	if j.ID != "job-1" {
		t.Errorf("decoded job id = %q, want job-1", j.ID)
	}
}

// `kura backup --local` is guarded: on-box execution needs the Phase 6
// storage backend, so it fails clearly rather than pretending to work.
func TestBackupLocalIsGuarded(t *testing.T) {
	fake := newFakeJobsServer(t)
	server := setupJobsCLITest(t, fake)

	_, _, err := runRoot(t, "backup", "--local", "--server", server)
	if err == nil {
		t.Fatal("backup --local returned no error")
	}
	if len(fake.submissions()) != 0 {
		t.Error("backup --local submitted a job; it should refuse before any network call")
	}
}

// A server rejection (e.g. 400 unknown kind when no backups store is
// wired) surfaces as a command error.
func TestBackupSurfacesServerError(t *testing.T) {
	fake := newFakeJobsServer(t)
	fake.submitStatus = http.StatusBadRequest
	server := setupJobsCLITest(t, fake)

	if _, _, err := runRoot(t, "backup", "--server", server); err == nil {
		t.Fatal("backup against a rejecting server returned no error")
	}
}
