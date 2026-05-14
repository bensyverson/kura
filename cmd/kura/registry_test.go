package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

// `kura agent-context` must be projected from the operations registry —
// the same registry that produces the CLI command also produces the JSON
// entry, so the command and its self-description cannot drift.
func TestAgentContextProjectedFromRegistry(t *testing.T) {
	cmd := newRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"agent-context"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("kura agent-context returned an error: %v", err)
	}

	var ctx struct {
		Version    string `json:"version"`
		Operations []struct {
			Name    string `json:"name"`
			Summary string `json:"summary"`
		} `json:"operations"`
	}
	if err := json.Unmarshal(out.Bytes(), &ctx); err != nil {
		t.Fatalf("agent-context output is not valid JSON: %v\n%s", err, out.String())
	}
	if ctx.Version == "" {
		t.Error("agent-context JSON must carry a version")
	}

	found := false
	for _, op := range ctx.Operations {
		if op.Name == "agent-context" {
			found = true
			if op.Summary == "" {
				t.Error("the agent-context operation is missing its summary")
			}
		}
	}
	if !found {
		t.Errorf("agent-context did not project its own registry entry:\n%s", out.String())
	}
}
