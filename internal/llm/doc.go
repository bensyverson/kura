// Package llm is Kura's LLM access gateway: the single path through
// which calls to an LLM provider (Anthropic by default) leave the
// system.
//
// The gateway is deliberately thin — it holds no policy of its own. It
// does three things:
//
//   - Fails closed at startup. NewGateway refuses to build a gateway for
//     a provider whose data processing agreement is not on file
//     (DPAConfig). This is a configuration check done once, at
//     construction, not per request — a provider with no DPA is one
//     Kura will not send data to.
//
//   - Logs metadata, never contents. Every Call writes a CallRecord —
//     timestamp, principal, model, token counts, and SHA-256 hashes of
//     the prompt and response. Like audit.Event, CallRecord has no field
//     that could carry the prompt or response themselves; the
//     contents-never guarantee is structural.
//
//   - Fails closed on the log. A Call whose metadata cannot be recorded
//     returns an error and no response.
//
// Provider is the seam: AnthropicProvider is the production
// implementation (the default data flow is the client owning the
// Anthropic account, so the API key is theirs, injected at runtime from
// the secrets manager), and FakeProvider is the in-memory double so the
// core's tests need no network.
package llm
