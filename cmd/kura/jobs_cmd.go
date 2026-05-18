package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bensyverson/kura/internal/clio"
	"github.com/bensyverson/kura/internal/jobs"
	"github.com/spf13/cobra"
)

// defaultWaitTimeout bounds `--wait` when the caller did not pass an
// explicit `--timeout`. Five minutes is long enough for the
// build-plan's targeted operations (a backup, a restore) and short
// enough that an agent that forgot the flag sees the poll loop give up
// rather than block its session.
const defaultWaitTimeout = 5 * time.Minute

// jobsPollInterval is how often `--wait` re-checks the job. The interval
// is deliberately small and steady: production jobs are server-side
// async, the network call is cheap, and an agent watching for a result
// wants steady feedback rather than exponential backoff. A var, not a
// const, so tests can dial it down for fast polling without changing
// the production default.
var jobsPollInterval = 500 * time.Millisecond

// newJobsCmd builds the `kura jobs` verb tree: list and get, plus the
// `--wait` flag that turns get into a poll-until-terminal loop. The
// ledger itself is server-side; this verb is a thin presenter.
func newJobsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jobs",
		Short: "Inspect and wait on async operations on the remote kura serve",
		Long: `Inspect and wait on async operations on the remote kura serve.

Jobs are server-side, durable, and idempotent: long-running operations
(backups, restores, provisioning) get a row in the ledger when they
start and progress through pending → running → succeeded/failed. A
retry from the same caller with the same idempotency key picks up the
existing job rather than spawning a duplicate, so it is safe to retry
freely.

Use ` + "`kura jobs list`" + ` to see your jobs, ` + "`kura jobs get <id>`" + ` to
read one. The same get supports ` + "`--wait`" + ` to poll until the job
reaches a terminal state, with ` + "`--timeout`" + ` bounding the wait.`,
	}
	cmd.AddCommand(newJobsListCmd())
	cmd.AddCommand(newJobsGetCmd())
	return cmd
}

// newJobsListCmd builds `kura jobs list`: GET /api/jobs. The ledger is
// actor-scoped on the server, so the caller sees only their own jobs.
func newJobsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the caller's async jobs, newest first",
		RunE: func(cmd *cobra.Command, _ []string) error {
			server, err := resolveServerFromFlags(cmd, "jobs list")
			if err != nil {
				return err
			}
			list, err := fetchJobs(cmd, server)
			if err != nil {
				return err
			}
			return renderJobs(cmd, list)
		},
	}
}

// newJobsGetCmd builds `kura jobs get <id>`: GET /api/jobs/{id}, with
// optional `--wait`/`--timeout`. The wait is a poll loop the CLI owns —
// the server itself is stateless on the wait, so a disconnected client
// just reconnects and reads the row again. SIGINT lands cleanly because
// the loop respects cmd.Context().
func newJobsGetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <id>",
		Short: "Read one job by id; with --wait, poll until it reaches a terminal status",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return clio.UsageError("jobs get", "exactly one job id is required")
			}
			id := args[0]
			server, err := resolveServerFromFlags(cmd, "jobs get")
			if err != nil {
				return err
			}
			wait, _ := cmd.Flags().GetBool("wait")
			timeout, _ := cmd.Flags().GetDuration("timeout")
			if !wait {
				j, err := fetchJob(cmd, server, id)
				if err != nil {
					return err
				}
				return renderJob(cmd, j)
			}
			if timeout <= 0 {
				timeout = defaultWaitTimeout
			}
			j, err := waitForJob(cmd, server, id, timeout)
			if err != nil {
				return err
			}
			return renderJob(cmd, j)
		},
	}
	cmd.Flags().Bool("wait", false, "poll until the job reaches a terminal status (succeeded or failed)")
	cmd.Flags().Duration("timeout", defaultWaitTimeout, "maximum time to wait when --wait is set (e.g. 30s, 2m, 1h)")
	return cmd
}

// fetchJobs GETs /api/jobs and decodes the response.
func fetchJobs(cmd *cobra.Command, server string) ([]jobs.Job, error) {
	resp, err := authedGet(cmd, "jobs list", strings.TrimRight(server, "/")+"/api/jobs")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, classifyHTTPStatus("jobs list", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		Jobs []jobs.Job `json:"jobs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, clio.InternalError("jobs list", "decoding server response: %w", err)
	}
	return out.Jobs, nil
}

// fetchJob GETs /api/jobs/{id} and decodes the response.
func fetchJob(cmd *cobra.Command, server, id string) (jobs.Job, error) {
	resp, err := authedGet(cmd, "jobs get", strings.TrimRight(server, "/")+"/api/jobs/"+id)
	if err != nil {
		return jobs.Job{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return jobs.Job{}, classifyHTTPStatus("jobs get", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var j jobs.Job
	if err := json.NewDecoder(resp.Body).Decode(&j); err != nil {
		return jobs.Job{}, clio.InternalError("jobs get", "decoding server response: %w", err)
	}
	return j, nil
}

// waitForJob polls fetchJob at jobsPollInterval until the job is
// terminal, the timeout fires, or the context is cancelled (SIGINT).
// The returned job is the final state the server reported; a timeout
// is its own clio.TransientError so an agent can retry.
func waitForJob(cmd *cobra.Command, server, id string, timeout time.Duration) (jobs.Job, error) {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(jobsPollInterval)
	defer ticker.Stop()

	// First check is immediate — if the job is already terminal, we
	// return before opening the timer.
	for {
		if err := cmd.Context().Err(); err != nil {
			return jobs.Job{}, clio.TransientError("jobs get", "wait cancelled: %w", err)
		}
		j, err := fetchJob(cmd, server, id)
		if err != nil {
			return jobs.Job{}, err
		}
		if isTerminalStatus(string(j.Status)) {
			return j, nil
		}
		if time.Now().After(deadline) {
			return j, clio.TransientError("jobs get", "wait timed out after %s; job %s is still %s — retry `kura jobs get %s --wait`",
				timeout, id, j.Status, id)
		}
		select {
		case <-cmd.Context().Done():
			return jobs.Job{}, clio.TransientError("jobs get", "wait cancelled: %w", cmd.Context().Err())
		case <-ticker.C:
		}
	}
}

// isTerminalStatus reports whether the wire status string is one of the
// terminal states. The CLI does not import the package's Status type's
// Terminal method directly — the wire shape is string-typed and the
// presenter stays decoupled from the server-side enum.
func isTerminalStatus(s string) bool {
	return s == string(jobs.StatusSucceeded) || s == string(jobs.StatusFailed)
}

// authedGet builds a GET request with the cached bearer token and runs
// it. The verb name lets clio.* errors surface the right context.
func authedGet(cmd *cobra.Command, verb, target string) (*http.Response, error) {
	cache, err := defaultTokenCache()
	if err != nil {
		return nil, err
	}
	_, token, err := cache.load()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, target, nil)
	if err != nil {
		return nil, clio.InternalError(verb, "building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, clio.TransientError(verb, "%w", err)
	}
	return resp, nil
}

// renderJobs writes a list of jobs to stdout — JSON or one-line
// Markdown each. The list is already in newest-first order from the
// server.
func renderJobs(cmd *cobra.Command, list []jobs.Job) error {
	useJSON, _ := cmd.Flags().GetBool("json")
	format := clio.FormatMarkdown
	if useJSON {
		format = clio.FormatJSON
	}
	payload := struct {
		Jobs []jobs.Job `json:"jobs"`
	}{Jobs: list}
	return clio.Render(cmd.OutOrStdout(), format, payload, func(w io.Writer) error {
		fmt.Fprintln(w, "# kura jobs")
		fmt.Fprintln(w)
		if len(list) == 0 {
			fmt.Fprintln(w, "no jobs on the ledger for this principal.")
			return nil
		}
		for _, j := range list {
			fmt.Fprintf(w, "- %s · %s/%s · created %s · %s\n",
				j.ID, j.Kind, j.Status,
				j.CreatedAt.UTC().Format(time.RFC3339),
				shortDuration(j))
		}
		return nil
	})
}

// renderJob writes one job to stdout — JSON if --json, a labeled
// summary otherwise. Error/result are written as JSON for the markdown
// view too: both are structured, both are short.
func renderJob(cmd *cobra.Command, j jobs.Job) error {
	useJSON, _ := cmd.Flags().GetBool("json")
	if useJSON {
		return clio.Render(cmd.OutOrStdout(), clio.FormatJSON, j, nil)
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "# job %s\n\n", j.ID)
	fmt.Fprintf(out, "- kind:    %s\n", j.Kind)
	fmt.Fprintf(out, "- status:  %s\n", j.Status)
	fmt.Fprintf(out, "- actor:   %s\n", j.Actor)
	fmt.Fprintf(out, "- idempotency_key: %s\n", j.IdempotencyKey)
	fmt.Fprintf(out, "- created: %s\n", j.CreatedAt.UTC().Format(time.RFC3339))
	if j.StartedAt != nil {
		fmt.Fprintf(out, "- started: %s\n", j.StartedAt.UTC().Format(time.RFC3339))
	}
	if j.FinishedAt != nil {
		fmt.Fprintf(out, "- finished: %s\n", j.FinishedAt.UTC().Format(time.RFC3339))
	}
	if len(j.Params) > 0 {
		fmt.Fprintf(out, "- params:  %s\n", string(j.Params))
	}
	if len(j.Result) > 0 {
		fmt.Fprintf(out, "- result:  %s\n", string(j.Result))
	}
	if j.Error != "" {
		fmt.Fprintf(out, "- error:   %s\n", j.Error)
	}
	return nil
}

// shortDuration renders the elapsed time of one job in a way that helps
// an agent scan the list. Pending/running show "queued"/"running for
// X"; terminal jobs show "X".
func shortDuration(j jobs.Job) string {
	switch j.Status {
	case jobs.StatusPending:
		return "queued"
	case jobs.StatusRunning:
		if j.StartedAt != nil {
			return "running for " + time.Since(*j.StartedAt).Round(time.Second).String()
		}
		return "running"
	}
	if j.StartedAt != nil && j.FinishedAt != nil {
		return j.FinishedAt.Sub(*j.StartedAt).Round(time.Millisecond).String()
	}
	return string(j.Status)
}
