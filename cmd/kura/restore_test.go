package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bensyverson/kura/internal/jobs"
)

// `kura restore` is wired as a real command carrying --wait.
func TestRestoreCommandIsWired(t *testing.T) {
	root := newRootCmd()
	cmd, _, err := root.Find([]string{"restore"})
	if err != nil {
		t.Fatalf("finding restore command: %v", err)
	}
	if cmd.Name() != "restore" {
		t.Fatalf("found command %q, want restore", cmd.Name())
	}
	if cmd.Flags().Lookup("wait") == nil {
		t.Error("restore command has no --wait flag")
	}
}

// restore requires the backup object key as a positional argument.
func TestRestoreRequiresObjectKey(t *testing.T) {
	fake := newFakeJobsServer(t)
	server := setupJobsCLITest(t, fake)

	if _, _, err := runRoot(t, "restore", "--confirm", "--server", server); err == nil {
		t.Fatal("restore with no object key returned no error")
	}
	if len(fake.submissions()) != 0 {
		t.Error("restore submitted a job despite missing object key")
	}
}

// restore is destructive, so it refuses without --confirm and never
// reaches the server.
func TestRestoreRequiresConfirm(t *testing.T) {
	fake := newFakeJobsServer(t)
	server := setupJobsCLITest(t, fake)

	_, _, err := runRoot(t, "restore", "backup-x.dump.enc", "--server", server)
	if err == nil {
		t.Fatal("restore without --confirm returned no error")
	}
	if !strings.Contains(err.Error(), "confirm") {
		t.Errorf("error %q does not mention --confirm", err)
	}
	if len(fake.submissions()) != 0 {
		t.Error("restore submitted a job without --confirm")
	}
}

// With --confirm, restore submits a job of kind "restore" carrying the
// object key in params, with an idempotency key derived from the object
// key so an accidental double-submit re-attaches rather than re-running.
func TestRestoreSubmitsRestoreJob(t *testing.T) {
	fake := newFakeJobsServer(t)
	server := setupJobsCLITest(t, fake)

	stdout, _, err := runRoot(t, "restore", "backup-x.dump.enc", "--confirm", "--server", server)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	subs := fake.submissions()
	if len(subs) != 1 {
		t.Fatalf("server received %d submissions, want 1", len(subs))
	}
	if subs[0].kind != "restore" {
		t.Errorf("submitted kind = %q, want restore", subs[0].kind)
	}
	var p struct {
		ObjectKey string `json:"object_key"`
	}
	if err := json.Unmarshal(subs[0].params, &p); err != nil {
		t.Fatalf("decoding submitted params: %v\n%s", err, subs[0].params)
	}
	if p.ObjectKey != "backup-x.dump.enc" {
		t.Errorf("params object_key = %q, want backup-x.dump.enc", p.ObjectKey)
	}
	if subs[0].key != "restore-backup-x.dump.enc" {
		t.Errorf("idempotency key = %q, want restore-backup-x.dump.enc", subs[0].key)
	}
	if !strings.Contains(stdout.String(), "job-1") {
		t.Errorf("output %q does not report the job id", stdout.String())
	}
}

// An explicit --idempotency-key overrides the object-key-derived default.
func TestRestoreHonorsExplicitIdempotencyKey(t *testing.T) {
	fake := newFakeJobsServer(t)
	server := setupJobsCLITest(t, fake)

	if _, _, err := runRoot(t, "restore", "backup-x.dump.enc", "--confirm", "--idempotency-key", "my-key", "--server", server); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if subs := fake.submissions(); len(subs) != 1 || subs[0].key != "my-key" {
		t.Fatalf("submissions = %+v, want one with key my-key", subs)
	}
}

// With --wait, restore polls until terminal.
func TestRestoreWaitPollsUntilTerminal(t *testing.T) {
	fake := newFakeJobsServer(t)
	fake.script = []map[string]any{
		{"id": "job-1", "kind": "restore", "status": "running", "actor": "a@b", "idempotency_key": "k", "created_at": "2026-05-18T10:00:00Z"},
		{"id": "job-1", "kind": "restore", "status": "succeeded", "actor": "a@b", "idempotency_key": "k", "created_at": "2026-05-18T10:00:00Z"},
	}
	server := setupJobsCLITest(t, fake)

	prev := jobsPollInterval
	jobsPollInterval = 5 * time.Millisecond
	defer func() { jobsPollInterval = prev }()

	stdout, _, err := runRoot(t, "restore", "backup-x.dump.enc", "--confirm", "--wait", "--timeout", "2s", "--server", server)
	if err != nil {
		t.Fatalf("restore --wait: %v", err)
	}
	if !strings.Contains(stdout.String(), string(jobs.StatusSucceeded)) {
		t.Errorf("output %q does not show the terminal status", stdout.String())
	}
}

// `kura restore --local` is guarded the same way backup is.
func TestRestoreLocalIsGuarded(t *testing.T) {
	fake := newFakeJobsServer(t)
	server := setupJobsCLITest(t, fake)

	_, _, err := runRoot(t, "restore", "backup-x.dump.enc", "--confirm", "--local", "--server", server)
	if err == nil {
		t.Fatal("restore --local returned no error")
	}
	if len(fake.submissions()) != 0 {
		t.Error("restore --local submitted a job; it should refuse before any network call")
	}
}
