// Package ops is the operations registry: the single source of truth from
// which the CLI, the MCP server, and `kura agent-context` are all
// projected. An operation registered here becomes a CLI command, an MCP
// tool, and an agent-context entry with no per-surface restatement — so
// the three surfaces cannot drift. The registry is explicit Go data, not
// reflection over types and not a separate schema file: one place to
// edit, nothing to keep in sync.
package ops

import "io"

// ContextVersion is the schema version of the agent-context document.
// It is "0" while Kura is pre-1.0.
const ContextVersion = "0"

// Arg is a typed argument to an Operation.
type Arg struct {
	Name     string `json:"name"`
	Summary  string `json:"summary"`
	Type     string `json:"type"`
	Required bool   `json:"required"`
}

// Operation is a single unit of Kura behavior. The same value is
// projected onto every agent surface; there is no per-surface
// re-declaration to drift.
type Operation struct {
	Name    string `json:"name"`
	Summary string `json:"summary"`
	Args    []Arg  `json:"args,omitempty"`

	// Handler runs the operation. It is never serialized into
	// agent-context.
	Handler func(args []string, out io.Writer) error `json:"-"`
}

// Registry is the ordered set of operations Kura exposes.
type Registry struct {
	ops []Operation
}

// Register appends an operation to the registry.
func (r *Registry) Register(op Operation) {
	r.ops = append(r.ops, op)
}

// All returns the registered operations in registration order.
func (r *Registry) All() []Operation {
	return r.ops
}

// AgentContext is the machine-readable description of every operation,
// emitted by `kura agent-context` so an agent never has to scrape help
// text.
type AgentContext struct {
	Version    string      `json:"version"`
	Operations []Operation `json:"operations"`
}

// Context projects the registry into the versioned agent-context document.
func (r *Registry) Context() AgentContext {
	return AgentContext{
		Version:    ContextVersion,
		Operations: r.All(),
	}
}
