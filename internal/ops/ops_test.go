package ops

import "testing"

func TestRegistryRegisterAndAll(t *testing.T) {
	var r Registry
	r.Register(Operation{Name: "alpha", Summary: "first"})
	r.Register(Operation{Name: "beta", Summary: "second"})

	all := r.All()
	if len(all) != 2 {
		t.Fatalf("expected 2 operations, got %d", len(all))
	}
	if all[0].Name != "alpha" || all[1].Name != "beta" {
		t.Errorf("operations not returned in registration order: %v", all)
	}
}

// The agent-context document must be a faithful projection of the
// registry — same names, same typed args — so the three surfaces (CLI,
// MCP, agent-context) cannot drift from one another.
func TestContextProjectsRegisteredOperations(t *testing.T) {
	var r Registry
	r.Register(Operation{
		Name:    "show",
		Summary: "show a record",
		Args:    []Arg{{Name: "id", Summary: "record id", Type: "string", Required: true}},
	})

	ctx := r.Context()
	if ctx.Version == "" {
		t.Error("agent-context must carry a version")
	}
	if len(ctx.Operations) != 1 {
		t.Fatalf("expected 1 operation in context, got %d", len(ctx.Operations))
	}
	op := ctx.Operations[0]
	if op.Name != "show" || op.Summary != "show a record" {
		t.Errorf("context did not project operation name/summary: %+v", op)
	}
	if len(op.Args) != 1 || op.Args[0].Name != "id" || op.Args[0].Type != "string" || !op.Args[0].Required {
		t.Errorf("context did not faithfully project typed args: %+v", op.Args)
	}
}
