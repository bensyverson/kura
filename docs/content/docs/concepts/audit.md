---
title: Audit log
weight: 5
---

Kura keeps an **append-only audit log**: a structured record of every
authentication, every authorization decision, and every data access. It is how a
deployment answers "who looked at what, and when" — the question at the centre of the
threat model.

## The cardinal rule: never the data itself

The audit log records *that* something happened and *who* did it — **never what the
data was**. An audit `Event` carries only structured metadata: a timestamp, the event
kind, the outcome, the actor (a Cedar principal), the action, a resource *identifier*
(entity name + record id), and the real client IP the request came from.

This is enforced structurally, not by discipline. The `Event` type has no field — no
byte slice, no map, no `interface{}` — that could hold opaque content, and the
recording API takes no parameter through which a field's *value* could be passed. A
test reflects over `Event` and fails the build if anyone ever adds such a field. There
is simply nowhere for client PII to land in the log.

## What gets logged, distinctly

| Kind | Records | Outcome |
|---|---|---|
| `authentication` | An attempt to sign in. | allowed / denied |
| `authorization` | A policy decision on an action against a resource. | allowed / denied |
| `access` | A data access that actually occurred. | always allowed — a denied attempt is an `authorization` event |

Authentication and authorization are separate kinds on purpose: an auditor needs to
tell "who got in" apart from "what they were allowed to touch."

Every gate path funnels through the `Recorder` — `RecordAuthentication`,
`RecordAuthorization`, `RecordAccess` — so emitting an audit event is not something a
caller can forget.

### The client IP rides the context

The real client IP is request-scoped, not something every `Record*` call should have
to thread by hand. The adapter serving a request sets it once at the boundary — the
HTTP API reads the forwarded `X-Forwarded-For` IP — and the `Recorder` reads it back
off the context for every event it writes. An event recorded outside a request, such
as a CLI-local access, simply carries an empty IP.

## Querying and streaming

The audit `Store` is append-only by the shape of its interface: it offers no update
and no delete. It exposes two read primitives, which the CLI's `log` / `tail` verbs
and the dashboard's audit viewer consume:

- **Query** — every event matching a filter on actor, resource entity, action, and an
  inclusive-`Since` / exclusive-`Until` time range.
- **Subscribe** — a live channel of events appended after the call, for `tail`.

### Over the HTTP API

The `kura serve` HTTP API projects both primitives as read-only endpoints:

| Endpoint | Returns |
|---|---|
| `GET /api/audit` | The events matching the `actor`, `entity`, `action`, `since`, and `until` query parameters. Time bounds are RFC 3339. |
| `GET /api/audit/stream` | A live `application/x-ndjson` feed — one event per line — of events appended after the request opens. |

**Reading the audit log is itself an audited event.** Both endpoints run through the
core gate as `review` operations, so a query or a stream is authorized against the
caller's roles — the `auditor` and `admin` roles may read, no one else — and the
access is recorded on the `audit_log` resource. There is no write endpoint: the log
is append-only, and only the `Recorder` on a gate path can append to it.

## Its own store, its own retention

The audit log is itself sensitive — but at a different category than the data it
guards. The production store targets its own object storage with its own retention
policy (build-plan Phases 1 and 6), separate from the primary database. The in-memory
store is what tests and the pre-database break-glass paths use.
