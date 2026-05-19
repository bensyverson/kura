package main

import (
	"github.com/bensyverson/kura/internal/ops"
	"testing"
)

// The agent-context Cobra command is still wired through the ops
// Registry — that is the seam shared with MCP. The handler walks the
// live Cobra tree at execution time (see agent_context_test.go for the
// command-tree assertions); this test just guards the registration.
func TestAgentContextRegisteredInOpsRegistry(t *testing.T) {
	r := buildRegistry(newRootCmd())
	var found *ops.Operation
	for _, op := range r.All() {
		if op.Name == "agent-context" {
			found = &op
			break
		}
	}
	if found == nil {
		t.Fatalf("agent-context is not registered in the ops Registry")
	}
	if found.Summary == "" {
		t.Error("the agent-context operation is missing its summary")
	}
	if found.Handler == nil {
		t.Error("the agent-context operation has no handler")
	}
}
