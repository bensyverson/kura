package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bensyverson/kura/internal/clio"
	"github.com/spf13/cobra"
)

// newLogCmd builds `kura log`: a filterable, one-shot read of the audit
// log over GET /api/audit. The filter axes — actor / resource / action /
// time — match the gate's audit.Filter shape; absent flags are
// "match any". The verb is a presenter over the wire response, which the
// server already gates as an AdminReview op (auditor or admin role).
func newLogCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "log",
		Short: "Read the audit log, filtered by actor/resource/action/time",
		Long: `Read the audit log over GET /api/audit, filtered.

Every flag is optional; absent flags are "match any". Time bounds are
RFC 3339 — --since is inclusive, --until is exclusive, so adjacent
windows tile without overlap. The server gates this as an AdminReview
operation, so the auditor role may read; reading the log is itself an
audited event.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			actor, _ := cmd.Flags().GetString("actor")
			resource, _ := cmd.Flags().GetString("resource")
			action, _ := cmd.Flags().GetString("action")
			since, _ := cmd.Flags().GetString("since")
			until, _ := cmd.Flags().GetString("until")
			if err := validateRFC3339("log", "--since", since); err != nil {
				return err
			}
			if err := validateRFC3339("log", "--until", until); err != nil {
				return err
			}
			server, err := resolveServerFromFlags(cmd, "log")
			if err != nil {
				return err
			}
			events, err := fetchAuditEvents(cmd, server, auditQuery{
				actor: actor, resource: resource, action: action, since: since, until: until,
			})
			if err != nil {
				return err
			}
			return renderAuditEvents(cmd, events)
		},
	}
	cmd.Flags().String("actor", "", "filter by actor id (principal email/id)")
	cmd.Flags().String("resource", "", "filter by resource entity name")
	cmd.Flags().String("action", "", "filter by action")
	cmd.Flags().String("since", "", "inclusive lower time bound (RFC 3339)")
	cmd.Flags().String("until", "", "exclusive upper time bound (RFC 3339)")
	return cmd
}

// newTailCmd builds `kura tail`: a live JSON-lines stream of audit
// events over GET /api/audit/stream. The server emits one
// application/x-ndjson event per line; the CLI prints each line and
// terminates cleanly on three things: stream close, context
// cancellation (SIGINT from main), or a decode error.
//
// Tail is JSON-shaped on stdout by default — the events are already
// machine-structured and the use case is piping into another tool. The
// `--json` flag is accepted for parity with the other verbs but does
// not change behavior; the Markdown view is also a JSON-lines stream,
// for the same reason.
func newTailCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tail",
		Short: "Stream audit events live as JSON lines",
		Long: `Stream audit events live, one JSON object per line.

Output is application/x-ndjson — exactly what the server sends, line
for line. Terminates cleanly on Ctrl-C (the SIGINT main wires into
cmd.Context), on the server closing the stream, or on a malformed
line. The server gates this as an AdminReview operation.`,
		RunE: runTail,
	}
}

// auditQuery is the parsed filter for fetchAuditEvents.
type auditQuery struct {
	actor, resource, action, since, until string
}

// validateRFC3339 surfaces an unparseable time as a usage error with
// the flag named in the first line — the agent sees the fix without
// reading the server's reply.
func validateRFC3339(verb, flag, raw string) error {
	if raw == "" {
		return nil
	}
	if _, err := time.Parse(time.RFC3339, raw); err != nil {
		return clio.UsageError(verb, "%s must be RFC 3339 (got %q): %w", flag, raw, err)
	}
	return nil
}

// fetchAuditEvents GETs /api/audit with the filter as query parameters
// and decodes the response. A 401/403/5xx flows through the shared
// taxonomy mapper, so the agent's error has the same shape as every
// other verb.
func fetchAuditEvents(cmd *cobra.Command, server string, q auditQuery) ([]auditEvent, error) {
	cache, err := defaultTokenCache()
	if err != nil {
		return nil, err
	}
	_, token, err := cache.load()
	if err != nil {
		return nil, err
	}
	params := url.Values{}
	if q.actor != "" {
		params.Set("actor", q.actor)
	}
	if q.resource != "" {
		params.Set("entity", q.resource)
	}
	if q.action != "" {
		params.Set("action", q.action)
	}
	if q.since != "" {
		params.Set("since", q.since)
	}
	if q.until != "" {
		params.Set("until", q.until)
	}
	target := strings.TrimRight(server, "/") + "/api/audit"
	if encoded := params.Encode(); encoded != "" {
		target += "?" + encoded
	}
	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, target, nil)
	if err != nil {
		return nil, clio.InternalError("log", "building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, clio.TransientError("log", "%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, classifyHTTPStatus("log", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		Events []auditEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, clio.InternalError("log", "decoding server response: %w", err)
	}
	return out.Events, nil
}

// auditEvent is the CLI's view of one wire-shape audit event. The
// fields mirror the server's auditEventJSON; the CLI is a presenter,
// not a re-modeler.
type auditEvent struct {
	Time     time.Time   `json:"time"`
	Kind     string      `json:"kind"`
	Outcome  string      `json:"outcome"`
	Actor    auditActor  `json:"actor"`
	Action   string      `json:"action,omitempty"`
	Resource auditTarget `json:"resource"`
	IP       string      `json:"ip,omitempty"`
}

type auditActor struct {
	Type   string `json:"type,omitempty"`
	ID     string `json:"id,omitempty"`
	Email  string `json:"email,omitempty"`
	Tenant string `json:"tenant,omitempty"`
}

type auditTarget struct {
	Entity string `json:"entity,omitempty"`
	ID     string `json:"id,omitempty"`
}

// renderAuditEvents writes the matched events to stdout. JSON emits
// {"events":[...]}; Markdown emits a one-line summary per event with
// the timestamp, kind/outcome, actor, action, and resource. Sorting is
// the server's call — the response is already in append order.
func renderAuditEvents(cmd *cobra.Command, events []auditEvent) error {
	useJSON, _ := cmd.Flags().GetBool("json")
	format := clio.FormatMarkdown
	if useJSON {
		format = clio.FormatJSON
	}
	payload := struct {
		Events []auditEvent `json:"events"`
	}{Events: events}
	return clio.Render(cmd.OutOrStdout(), format, payload, func(w io.Writer) error {
		fmt.Fprintln(w, "# kura log")
		fmt.Fprintln(w)
		if len(events) == 0 {
			fmt.Fprintln(w, "no events match — widen the filter, or check the time window.")
			return nil
		}
		for _, e := range events {
			fmt.Fprintf(w, "- %s · %s/%s · %s · %s · %s\n",
				e.Time.UTC().Format(time.RFC3339),
				e.Kind, e.Outcome,
				orDash(e.Actor.Email, e.Actor.ID),
				orDash(e.Action),
				formatTarget(e.Resource))
		}
		return nil
	})
}

// orDash returns the first non-empty option, or "-" if all are empty —
// the dash is a deliberate placeholder so a Markdown table-style row
// always has the same column count.
func orDash(opts ...string) string {
	for _, s := range opts {
		if s != "" {
			return s
		}
	}
	return "-"
}

// formatTarget renders an audit Resource as `entity/id` (or just
// `entity` when no id is set; "-" when neither is set).
func formatTarget(t auditTarget) string {
	switch {
	case t.Entity != "" && t.ID != "":
		return t.Entity + "/" + t.ID
	case t.Entity != "":
		return t.Entity
	default:
		return "-"
	}
}

// runTail opens the audit stream and prints each NDJSON line until the
// stream ends, the context cancels, or a decode error surfaces. The
// CLI does not buffer or batch — every line the server writes is one
// line on stdout, immediately, so an agent piping into another tool
// sees events the moment they arrive.
func runTail(cmd *cobra.Command, _ []string) error {
	server, err := resolveServerFromFlags(cmd, "tail")
	if err != nil {
		return err
	}
	cache, err := defaultTokenCache()
	if err != nil {
		return err
	}
	_, token, err := cache.load()
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, strings.TrimRight(server, "/")+"/api/audit/stream", nil)
	if err != nil {
		return clio.InternalError("tail", "building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/x-ndjson")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// A done context surfaces here as the request errors out — a
		// SIGINT (context.Canceled) or a deadline (context.DeadlineExceeded)
		// is a clean termination, not a failure.
		if cmd.Context().Err() != nil {
			return nil
		}
		return clio.TransientError("tail", "%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return classifyHTTPStatus("tail", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return streamAuditLines(cmd.Context(), resp.Body, cmd.OutOrStdout())
}

// streamAuditLines copies NDJSON lines from r to out until r ends, ctx
// cancels, or a read fails. Pulled out so a test can drive it
// synchronously without standing up an http server.
func streamAuditLines(ctx context.Context, r io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		if _, err := fmt.Fprintln(out, string(line)); err != nil {
			return clio.InternalError("tail", "writing line: %w", err)
		}
	}
	if err := scanner.Err(); err != nil {
		// A done context closes the underlying body, which surfaces
		// here as a read error — that is the clean-termination path
		// (SIGINT or a deadline both qualify).
		if ctx.Err() != nil {
			return nil
		}
		return clio.TransientError("tail", "%w", err)
	}
	return nil
}
