package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/bensyverson/kura/internal/clio"
	"github.com/bensyverson/kura/internal/identity"
	"github.com/spf13/cobra"
)

// newStatusCmd builds `kura status`: the session opener.
//
// The CLI design guidelines pin `status` as the first call an agent
// makes every session — a single document that names the server,
// resolves the principal, and surfaces anything that needs attention.
// The job CLI's `job status` is the same shape: identity check plus
// landscape briefing in one round-trip.
//
// What status reports today (Phase 3):
//
//   - server: the resolved server URL (which precedence won is
//     visible from the corresponding flag values an agent has at hand)
//   - identity: the principal /api/whoami returns for the cached token
//   - tier and anomalies: placeholders. These fields exist in the
//     document on purpose so an agent parses one stable shape across
//     phases; their values become real once Phase 6 (deployment tier)
//     and the audit-anomalies surface come online.
//
// status uses the same Markdown-default / --json opt-in / classified-
// error contract as every other verb. A non-2xx response is mapped
// through classifyHTTPStatus to the right Kind.
func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Session opener: identity check and landscape briefing",
		Long: `Session opener — run this first, every session.

status answers the four orienting questions in one document:
- which server you are talking to;
- who that server resolves you as;
- what deployment tier the server is running on (Phase 6+);
- whether any audit anomalies need your attention (Phase 8+).

Output defaults to dense Markdown; pass --json for the stable schema.`,
		RunE: runStatus,
	}
}

// statusReport is the document `kura status` emits. The shape is
// stable across phases: tier and anomalies are present even while
// their values are placeholders, so callers parse one schema. New
// fields go at the end and are documented in
// docs/content/docs/machine-interface/cli-output.md.
type statusReport struct {
	Server    string             `json:"server"`
	Identity  identity.Principal `json:"identity"`
	Tier      string             `json:"tier"`
	Anomalies []string           `json:"anomalies"`
}

// runStatus is the command's RunE. It is a small composition: resolve
// the server, load the cached token, fetch whoami, and build the
// report. Every error along the way is already a *clio.Error from the
// helpers — there is nothing for status to wrap.
func runStatus(cmd *cobra.Command, _ []string) error {
	server, err := resolveServerFromFlags(cmd, "status")
	if err != nil {
		return err
	}
	principal, err := fetchPrincipal(cmd, server)
	if err != nil {
		return err
	}
	report := statusReport{
		Server:   server,
		Identity: principal,
		// Tier and anomalies are placeholders until the corresponding
		// subsystems land. The fields exist now so the document shape is
		// stable for early agents; the values will become real without a
		// schema change.
		Tier:      "unknown (Phase 6+)",
		Anomalies: []string{},
	}

	useJSON, _ := cmd.Flags().GetBool("json")
	format := clio.FormatMarkdown
	if useJSON {
		format = clio.FormatJSON
	}
	return clio.Render(cmd.OutOrStdout(), format, report, func(w io.Writer) error {
		fmt.Fprintf(w, "# kura status\n\n")
		fmt.Fprintf(w, "- server: %s\n", report.Server)
		fmt.Fprintf(w, "- identity: %s (%s) — tenant %s\n", report.Identity.Email, report.Identity.Type, report.Identity.Tenant)
		fmt.Fprintf(w, "- tier: %s\n", report.Tier)
		fmt.Fprintf(w, "- anomalies: %d\n", len(report.Anomalies))
		fmt.Fprintln(w)
		fmt.Fprintf(w, "Next: pick a verb (`kura --help`) or run `kura agent-context` for the machine-readable command tree.\n")
		return nil
	})
}

// fetchPrincipal is the shared "ask the server who I am" helper used
// by status today and by future session-aware verbs. It loads the
// cached token, hits /api/whoami, and returns the decoded principal —
// everything along the way is already a *clio.Error.
func fetchPrincipal(cmd *cobra.Command, server string) (identity.Principal, error) {
	cache, err := defaultTokenCache()
	if err != nil {
		return identity.Principal{}, err
	}
	_, token, err := cache.load()
	if err != nil {
		return identity.Principal{}, err
	}
	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, strings.TrimRight(server, "/")+"/api/whoami", nil)
	if err != nil {
		return identity.Principal{}, clio.InternalError("status", "building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return identity.Principal{}, clio.TransientError("status", "%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return identity.Principal{}, classifyHTTPStatus("status", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var p identity.Principal
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return identity.Principal{}, clio.InternalError("status", "decoding server response: %w", err)
	}
	return p, nil
}
