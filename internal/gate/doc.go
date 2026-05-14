// Package gate is the core enforcement assembly — "the core is the gate"
// made concrete. It ties the enforcement subsystems into the single
// entrypoint every adapter calls:
//
//	authenticate -> authorize -> access -> mask -> audit
//
// The HTTP API, the CLI's --local path, the local dashboard, and the MCP
// server all go through Gate.Access and nothing else. None of them may
// reconstruct any of these steps themselves — that is the whole point of
// the package.
//
// The chain is welded shut by construction, not by convention:
//
//   - There is no public method that performs a subset. Gate exposes one
//     verb, Access; you run the whole chain or you get nothing.
//
//   - The data read is a caller-supplied Fetcher, but the gate owns when
//     it runs (only after authorization passes) and what happens to its
//     output (masked and audited before return). A Fetcher is not a way
//     around the gate — its result never leaves the gate unmasked.
//
//   - Masking is identical for every caller because it happens here. The
//     Redacted constant and the span-level redaction in mask.go are not
//     reachable or overridable by an adapter.
//
//   - A step that cannot be audited fails the whole request closed: an
//     access Kura cannot record is one it does not return.
//
// Authorization reasons about PII categories, never column names: the
// categories come from the manifest at decide time, and the data is
// re-scanned at mask time so detector drift since ingestion is caught.
package gate
