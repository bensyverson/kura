---
title: CLI audit verbs — log & tail
weight: 7
---

The audit log is the auditable, append-only record of every authentication, authorization, and data access decision the gate has made. `kura log` reads it, filtered; `kura tail` streams new events live. Both are read-only — the log is append-only and **the API exposes no way to write to it out of band**.

Both verbs go through the gate as `AdminReview` operations: the auditor role and the admin role may read, plain users get a 403, and *reading the log is itself an audited event* (recorded against the `audit_log` resource, so an auditor can tell log reads apart from data reads).

## The verbs

```sh
kura log [--actor ID] [--resource ENTITY] [--action ACT] [--since RFC3339] [--until RFC3339]
kura tail
```

## `kura log` — filtered, one-shot

`kura log` queries `GET /api/audit` with the filter axes the gate's `audit.Filter` exposes. Every flag is optional; absent flags are "match any":

- `--actor <id>` — match `Event.Actor.ID` (typically the email).
- `--resource <entity>` — match `Event.Resource.Entity` (the entity name; the CLI flag is called `--resource` because that's what the audit event calls it, even though the server's wire param is `entity`).
- `--action <action>` — match `Event.Action`.
- `--since <RFC 3339>` — inclusive lower time bound.
- `--until <RFC 3339>` — exclusive upper time bound, so adjacent windows tile without overlap.

Malformed time bounds are caught client-side as a usage error that names the offending flag — the server never sees a bad bound.

The Markdown view emits one line per event with the timestamp, kind/outcome, actor, action, and resource. `--json` emits `{"events": [...]}` with the full server schema; pipe it into `jq` or another tool when you need structured access.

## `kura tail` — live JSON lines

`kura tail` opens `GET /api/audit/stream` and prints every appended event as one JSON object per line — application/x-ndjson, exactly what the server sends, line for line. The CLI does not batch or transform; an agent piping `kura tail | jq` sees events the moment they arrive.

Termination is clean on all three of the natural endings:

- **Ctrl-C (SIGINT)** — `main.go` wires `signal.NotifyContext` into the root command's context, so a SIGINT cancels `cmd.Context()`, which closes the HTTP request, which ends the scanner loop. `kura tail` returns nil; exit code is zero.
- **Server closes the stream** — the scanner loop ends; same nil return.
- **Malformed line** — surfaced as a `KindTransient` error so an agent knows to retry.

`tail` does not retry on disconnect. Reconnection is the caller's job; an agent that wants resilient streaming wraps `kura tail` in its own loop with whatever backoff policy fits.

## What an event looks like

Every event carries identifiers only — never field values. The wire shape:

```json
{
  "time": "2026-05-18T10:00:00Z",
  "kind": "access",
  "outcome": "allowed",
  "actor": {"type": "user", "id": "alex@client.com", "email": "alex@client.com", "tenant": "client.com"},
  "action": "read",
  "resource": {"entity": "patient", "id": "p1"},
  "ip": "203.0.113.7"
}
```

`kind` is one of `authentication`, `authorization`, `access`; `outcome` is `allowed` or `denied`. There is no field-value payload on an audit event by design — see `internal/audit` package docs.

## Output and errors

Both verbs follow the shared contract from [CLI output & errors](../cli-output):

- `KindUsage` (exit 2) on a malformed `--since` / `--until`.
- `KindAuth` (exit 3) on 401/403 — typically the caller is not an admin or an auditor.
- `KindTransient` (exit 6) on 5xx or on a stream read error mid-flight.
- `KindInternal` (exit 1) on a decode failure (the server sent bytes the CLI cannot parse).
