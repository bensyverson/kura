---
title: LLM access gateway
weight: 10
---

Calls to an LLM provider — Anthropic by default — leave Kura through one
thin gateway. The gateway holds **no policy of its own**; it is wiring around
a provider that does exactly three things.

## 1. Fails closed at startup if no DPA is on file

The gateway refuses to exist for a provider whose **data processing agreement**
is not on file. This is a configuration check done **once, at startup** — not
per request. `NewGateway` returns `ErrDPANotOnFile` and no gateway when the
provider's DPA is not attested in the `DPAConfig`. A provider with no DPA is
one Kura will not send data to, so there is simply no working gateway for it.

## 2. Logs metadata, never contents

Every call writes a `CallRecord` to an append-only metadata log:

| Recorded | Never recorded |
| --- | --- |
| Timestamp, principal, model | The prompt |
| Input / output token counts | The response |
| SHA-256 hash of the prompt | |
| SHA-256 hash of the response | |

Like `audit.Event`, `CallRecord` has **no field** that could carry the prompt
or response themselves — the contents-never guarantee is structural, not a
matter of discipline. A hash is a fingerprint: it lets an auditor correlate or
detect tampering without the log ever holding what was sent to the provider.

This is a **separate log** from the general audit log (`internal/audit`). An
LLM call is a different kind of event with different metadata; reusing the
audit `Event` type would have meant widening it with LLM-specific fields. The
contents-never guarantee is identical in both.

## 3. Fails closed if the call cannot be logged

A call whose metadata cannot be recorded returns an error and **no response**.
An LLM call Kura cannot log is one it does not return.

## Data flow

The default data flow is the **client owning the Anthropic account** — the
cleanest path. The `AnthropicProvider` authenticates with the client's API
key, injected at runtime from the secrets manager, never baked into an image
or committed. `FakeProvider` is the in-memory double so the core's tests need
no network.

The Heavily-Regulated tier routes to the provider over a private network path
(Bedrock VPC endpoint, Vertex Private Service Connect); that is an
infrastructure concern, not a change to this gateway.

## Over the HTTP API

The `kura serve` HTTP API exposes the gateway as one endpoint:

| Endpoint | Body |
| --- | --- |
| `POST /api/llm` | Request: `{ "model", "prompt", "max_tokens" }`. Response: `{ "content", "input_tokens", "output_tokens" }`. |

Callers go through this endpoint rather than calling the provider directly, so
the DPA check and the metadata logging are enforced for every call — there is
no other path to the provider.

If the **startup DPA check failed** there is no gateway, and the endpoint
**refuses to serve**: it answers `503 Service Unavailable` rather than `404`,
so the endpoint's absence is a reported condition, not a silent gap. The server
itself still runs — a missing DPA disables the LLM endpoint, it does not stop
`kura serve`. The endpoint is wired from `KURA_ANTHROPIC_API_KEY` and
`KURA_ANTHROPIC_DPA_ON_FILE`; without either, it is unavailable.
