package main

import (
	"github.com/bensyverson/kura/internal/backup"
	"github.com/bensyverson/kura/internal/clio"
	"github.com/spf13/cobra"
)

// newBackupCmd builds `kura backup`: trigger the independent
// logical-backup tier on the remote kura serve. The orchestration —
// pg_dump, encryption with a secrets-sourced key distinct from the
// runtime keys, and an append-only write to the separate-region backups
// bucket — runs server-side as an async job; this verb is a thin
// presenter that submits the job and, with --wait, polls it to terminal.
func newBackupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Trigger an encrypted database backup on the remote kura serve",
		Long: `Trigger the independent logical-backup tier on the remote kura serve.

The backup is dumped, encrypted with a key sourced from the secrets
backend (distinct from the runtime field-encryption keys), and written
to the separate-region backups bucket through the append-only storage
role. It runs as a server-side async job and is recorded on the jobs
ledger; use ` + "`--wait`" + ` to poll until it finishes, or read it later
with ` + "`kura jobs get <id>`" + `.

Submitting a backup is an admin operation. A retry with the same
` + "`--idempotency-key`" + ` re-attaches to the in-flight job rather than
starting a second backup.`,
		RunE: backupRun,
	}
	cmd.Flags().Bool("wait", false, "poll until the backup job reaches a terminal status (succeeded or failed)")
	cmd.Flags().Duration("timeout", defaultWaitTimeout, "maximum time to wait when --wait is set (e.g. 30s, 2m, 1h)")
	cmd.Flags().String("idempotency-key", "", "reuse a key to re-attach to an in-flight backup instead of starting a new one")
	return cmd
}

// backupRun submits a backup job and reports it, optionally waiting for
// it to finish.
func backupRun(cmd *cobra.Command, args []string) error {
	if len(args) != 0 {
		return clio.UsageError("backup", "backup takes no arguments")
	}
	if local, _ := cmd.Flags().GetBool("local"); local {
		return clio.UsageError("backup", "--local backup needs the on-box storage backend, which lands in the deployment baseline (Phase 6); run against a remote kura serve for now")
	}

	server, err := resolveServerFromFlags(cmd, "backup")
	if err != nil {
		return err
	}

	key, _ := cmd.Flags().GetString("idempotency-key")
	if key == "" {
		key = newIdempotencyKey()
	}

	// No params: the server stamps the authenticated principal in, and a
	// backup has no other inputs.
	j, err := submitJob(cmd, "backup", server, backup.KindBackup, key, nil)
	if err != nil {
		return err
	}

	if wait, _ := cmd.Flags().GetBool("wait"); wait {
		timeout, _ := cmd.Flags().GetDuration("timeout")
		if timeout <= 0 {
			timeout = defaultWaitTimeout
		}
		j, err = waitForJob(cmd, server, j.ID, timeout)
		if err != nil {
			return err
		}
	}
	return renderJob(cmd, j)
}
