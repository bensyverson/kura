---
title: CLI jobs verbs — list, get, --wait
weight: 8
---

A **job** is an async operation Kura runs server-side: a backup, a restore, a provisioning step — anything that takes too long to belong in a single HTTP call. The **jobs ledger** is the durable record of every one of these operations, with two cardinal properties:

- **Idempotency.** A retry with the same `(actor, kind, idempotency_key)` finds the existing job rather than spawning a duplicate. Retrying is always safe.
- **Survives a process restart.** The ledger is persisted in Postgres; a worker that crashed mid-job is recovered on startup, and the next worker picks up the pending row exactly once.

`kura jobs` is the read side of that ledger. The verbs that *produce* jobs — `kura backup` and `kura restore` in the next build-plan phase — call the same `POST /api/jobs` under the hood; nothing about the wire shape changes.

## The verbs

```sh
kura jobs list
kura jobs get <id> [--wait] [--timeout DUR]
```

Both go through the gate. `list` and `get` are `AdminReview` (auditor or admin); submit is `AdminManage` (admin only). Every call is audited like any other action.

## `kura jobs list` — the ledger, newest first

`kura jobs list` queries `GET /api/jobs` and renders the caller's jobs as one line each: the id, the `kind/status` pair, the creation time, and a short duration that tells you "queued", "running for X", or the elapsed wall time of a terminal job.

The ledger is **actor-scoped on read**: each caller sees only the jobs they submitted. A second admin doesn't see yours.

`--json` emits `{"jobs": [...]}` with the full server schema.

## `kura jobs get <id>` — one job, optionally waited

Without `--wait`, `kura jobs get <id>` is a single read. With `--wait`, it polls until the job reaches a terminal status (`succeeded` or `failed`) or `--timeout` fires. The poll is server-stateless: the CLI just hits `GET /api/jobs/{id}` every 500 ms, so a disconnected client just reconnects and reads the same row again — there is nothing to resume.

```sh
kura jobs get j-abc123                            # one-shot read
kura jobs get j-abc123 --wait                     # poll until terminal (default 5m timeout)
kura jobs get j-abc123 --wait --timeout 1h        # longer wait
```

`--wait` respects `cmd.Context()`, so **Ctrl-C cancels cleanly** the same way it does for `kura tail`. The exit code is the taxonomy: `KindTransient` for a timeout (agent can retry), `KindAuthorization` for a 403, `KindNotFound` for a 404 from the server.

## Idempotency & retry-finds-existing-work

The ledger's key invariant: re-submitting the same logical job (same actor, same kind, same `idempotency_key`) returns the existing row — same id, same status, same in-flight work. The caller doesn't have to track the id across a process crash to avoid duplicating a backup.

The server response to `POST /api/jobs` makes this explicit:

```json
{ "job": { "id": "j-abc123", "kind": "backup", "status": "running", ... },
  "created": false }
```

`created: false` means "this is the existing job for that key". `created: true` means a new row was inserted. An agent that needs to know which is which reads the flag; an agent that just wants the job by name reads `job.id` regardless.

## What a job looks like

The wire shape mirrors `internal/jobs.Job`:

```json
{
  "id": "j-abc123",
  "kind": "backup",
  "status": "succeeded",
  "actor": "admin@client.com",
  "idempotency_key": "nightly-2026-05-18",
  "params": { "target": "primary" },
  "result": { "bucket": "kura-backups", "key": "..." },
  "error": "",
  "created_at":  "2026-05-18T10:00:00Z",
  "started_at":  "2026-05-18T10:00:01Z",
  "finished_at": "2026-05-18T10:00:42Z"
}
```

The four `status` values are `pending`, `running`, `succeeded`, and `failed`. The first two are non-terminal; `--wait` returns when one of the last two lands.

## Where the contract is enforced

- **The ledger itself**: `internal/jobs/` (the package), `internal/migrations/0005_jobs.sql` (the table, with `UNIQUE (tenant_id, actor, kind, idempotency_key)`).
- **The endpoints**: `internal/server/jobs.go` mounts `POST /api/jobs`, `GET /api/jobs`, and `GET /api/jobs/{id}`, each going through `gate.Admin`.
- **The CLI**: `cmd/kura/jobs_cmd.go` is wiring; it owns the poll loop for `--wait` and nothing else.

The actor on the row is whoever submitted it (the principal's email). Tenant isolation lands through the same RLS policy that scopes records and users.
