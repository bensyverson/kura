package main

import (
	"fmt"
	"io"

	"github.com/bensyverson/kura/internal/clio"
	"github.com/bensyverson/kura/internal/smoke"
	"github.com/spf13/cobra"
)

// newSmokeCmd builds `kura smoke`: run the end-to-end health suite
// against a target server and report pass/fail per check. The same
// command serves CI's ephemeral deploy, the staging environment, and the
// provisioning agent's per-engagement Definition of Done, so it speaks
// only to the public HTTP surface and needs no credential — one of its
// checks deliberately confirms the gate rejects an unauthenticated
// request.
//
// The outcome maps onto the exit-code taxonomy three ways: a clean pass
// exits 0, a reachable-but-failing server exits 7 (internal — the
// deployment is broken, escalate), and an unreachable server exits 6
// (transient — it may just not be up yet, retry).
func newSmokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "smoke",
		Short: "Run the end-to-end smoke suite against a target server",
		Long: `Run the end-to-end smoke suite against a target server.

Each check probes the public HTTP surface of a running ` + "`kura serve`" + ` and
reports pass or fail. No credential is required — one check confirms the
gate rejects an unauthenticated request.

The exit code classifies the run for an automated caller:

  0   every check passed
  6   the server was unreachable (may not be up yet — retry)
  7   the server was reachable but a check failed (escalate)

Point it with ` + "`--server <url>`" + `, a ` + "`--client`" + ` profile, or the cached
login. Use it as CI's post-deploy gate, a staging probe, or the
provisioning agent's Definition of Done.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			server, err := resolveServerFromFlags(cmd, "smoke")
			if err != nil {
				return err
			}
			rep := smoke.DefaultSuite(server).Run(cmd.Context(), nil)
			if err := renderSmokeReport(cmd, rep); err != nil {
				return err
			}
			return smokeOutcomeError(rep)
		},
	}
}

// smokeOutcomeError maps a report's outcome onto the exit-code taxonomy.
// A pass is nil (exit 0); a reachable failure escalates (Internal, exit
// 7); an unreachable server is retryable (Transient, exit 6).
func smokeOutcomeError(rep smoke.Report) error {
	switch rep.Outcome {
	case smoke.OutcomePass:
		return nil
	case smoke.OutcomeUnreachable:
		return clio.TransientError("smoke", "server %s is unreachable — is `kura serve` running and the URL correct?", rep.BaseURL)
	default:
		return clio.InternalError("smoke", "%d of %d checks failed against %s", countFailed(rep), len(rep.Results), rep.BaseURL)
	}
}

// countFailed returns the number of failing results in a report.
func countFailed(rep smoke.Report) int {
	n := 0
	for _, r := range rep.Results {
		if !r.Passed {
			n++
		}
	}
	return n
}

// renderSmokeReport writes the per-check report — JSON when --json,
// dense Markdown otherwise. The report is printed for every outcome,
// including failures, so the caller always sees which check failed
// before reading the exit code.
func renderSmokeReport(cmd *cobra.Command, rep smoke.Report) error {
	useJSON, _ := cmd.Flags().GetBool("json")
	format := clio.FormatMarkdown
	if useJSON {
		format = clio.FormatJSON
	}
	return clio.Render(cmd.OutOrStdout(), format, rep, func(w io.Writer) error {
		fmt.Fprintf(w, "# smoke %s\n\n", rep.BaseURL)
		for _, r := range rep.Results {
			marker := "PASS"
			if !r.Passed {
				marker = "FAIL"
			}
			fmt.Fprintf(w, "- [%s] %s — %s\n", marker, r.Name, r.Desc)
			if !r.Passed && r.Detail != "" {
				fmt.Fprintf(w, "    %s\n", r.Detail)
			}
		}
		fmt.Fprintf(w, "\noutcome: %s\n", rep.Outcome)
		return nil
	})
}
