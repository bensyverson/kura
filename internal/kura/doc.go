// Package kura is the core enforcement library: Cedar authorization, audit
// logging, PII detection/masking, field-level encryption, and data access.
//
// This is the product. The CLI, the HTTP API (kura serve), the local
// dashboard (kura dashboard), and the MCP server (kura mcp) are all thin
// adapters over this package. Any policy decision, audit write, or masking
// rule that lives in an adapter instead of here is a bug.
//
// See project/2026-05-14-architecture.md for the rationale.
package kura
