package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/bensyverson/kura/internal/clio"
	"github.com/spf13/cobra"
)

// newEdgesCmd builds `kura edges <entity> <id> --direction out|in`: a
// record's relationship edges, in one direction. "out" lists the record's
// own outgoing relationships (the edges it declared at creation); "in" lists
// the incoming edges that point at it, which the server orders by the source
// record's sequence — a deterministic, clock-skew-immune order.
//
// The direction is required: a caller asks for one view of a record's
// connections explicitly, never an implied default. Like `show`, this verb
// does not traverse relationships — an edge carries ids and a relationship
// name, not the related records' fields. Fetch a target with a second
// `kura show`.
func newEdgesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "edges <entity> <id>",
		Short: "List a record's relationship edges in one direction",
		Long: `List a record's relationship edges in one direction.

--direction is required:
  out  the record's own outgoing relationships (the edges it declared)
  in   the incoming edges that point at the record, ordered by the source
       record's sequence

Each edge is a relationship name and the source and target record ids, plus
the source record's sequence. Edges carry ids, not field values: this verb
does not follow relationships. Use a second ` + "`kura show`" + ` to fetch a
target record.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 2 {
				return clio.UsageError("edges", "exactly one entity name and one id are required")
			}
			entity, id := args[0], args[1]
			direction, _ := cmd.Flags().GetString("direction")
			if direction != "out" && direction != "in" {
				return clio.UsageError("edges", `--direction must be "out" or "in"`)
			}
			server, err := resolveServerFromFlags(cmd, "edges")
			if err != nil {
				return err
			}
			edges, err := fetchEdges(cmd, server, entity, id, direction)
			if err != nil {
				return err
			}
			return renderEdges(cmd, entity, id, direction, edges)
		},
	}
	cmd.Flags().String("direction", "", `which edges to list: "out" (the record's own relationships) or "in" (edges pointing at it)`)
	return cmd
}

// edgeView is one edge in the edges endpoint's response: the relationship
// name, the two record ids it connects, and the source record's order key.
type edgeView struct {
	Relationship string `json:"relationship"`
	SourceID     string `json:"source_id"`
	SourceSeq    int64  `json:"source_seq"`
	TargetID     string `json:"target_id"`
}

// edgesResult is the CLI's view of `GET /api/{entity}/{id}/edges`: the
// record's edges in the requested direction.
type edgesResult struct {
	Edges []edgeView `json:"edges"`
}

// fetchEdges GETs /api/{entity}/{id}/edges?direction=... with the cached
// bearer token. A non-2xx is classified through the shared HTTP-status mapper
// so the taxonomy is uniform across verbs.
func fetchEdges(cmd *cobra.Command, server, entity, id, direction string) (edgesResult, error) {
	cache, err := defaultTokenCache()
	if err != nil {
		return edgesResult{}, err
	}
	_, token, err := cache.load()
	if err != nil {
		return edgesResult{}, err
	}
	target := strings.TrimRight(server, "/") + "/api/" + url.PathEscape(entity) + "/" + url.PathEscape(id) + "/edges?direction=" + url.QueryEscape(direction)
	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, target, nil)
	if err != nil {
		return edgesResult{}, clio.InternalError("edges", "building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return edgesResult{}, clio.TransientError("edges", "%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return edgesResult{}, classifyHTTPStatus("edges", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out edgesResult
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return edgesResult{}, clio.InternalError("edges", "decoding server response: %w", err)
	}
	return out, nil
}

// renderEdges writes the edges to stdout — JSON for machines, dense Markdown
// otherwise. The Markdown view names the direction so a reader knows whether
// they are looking at outgoing or incoming connections.
func renderEdges(cmd *cobra.Command, entity, id, direction string, edges edgesResult) error {
	useJSON, _ := cmd.Flags().GetBool("json")
	format := clio.FormatMarkdown
	if useJSON {
		format = clio.FormatJSON
	}
	return clio.Render(cmd.OutOrStdout(), format, edges, func(w io.Writer) error {
		fmt.Fprintf(w, "# kura edges %s %s (%s)\n\n", entity, id, direction)
		if len(edges.Edges) == 0 {
			fmt.Fprintf(w, "no %s edges for this record.\n", direction)
			return nil
		}
		for _, e := range edges.Edges {
			fmt.Fprintf(w, "- **%s**: %s → %s (seq %d)\n", e.Relationship, e.SourceID, e.TargetID, e.SourceSeq)
		}
		return nil
	})
}
