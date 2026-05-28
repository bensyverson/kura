# Plan: fvbRA — `kura backup` / `kura restore` + async jobs wiring

## Context (why)

`fvbRA` ("Backup and restore commands") is the last open leaf of Phase 3 (CLI). Its **core orchestration is already built and tested** in `internal/backup/` (`pg_dump` → AES-256-GCM with a secrets-sourced key distinct from the field-encryption key → `storage.Store.Put` via the append-only role; restore reverses it; both audited; both registered as job kinds; real-Postgres round-trip in `integration_test.go`). What's missing is the **adapter layer**: the actual `kura backup` / `kura restore` CLI verbs and the `serve.go` wiring that registers the handlers and runs them through a restart-survivable jobs ledger.

A prior agent deferred this to Phase 6, reasoning it needed prod infra. That was over-cautious: per the adapter-over-core rule, `cmd/` is thin wiring, and the async infrastructure already exists (`jobs.NewPostgresStore`, migration `0005_jobs.sql`, the worker loop, the admin-gated `POST /api/jobs` endpoint, `backup.Service.Register`). So this task is wiring + thin verbs + tests — buildable now against interfaces, with the concrete DO Spaces `Store` client and the scheduled timer correctly staying in Phase 6.

## Decisions (confirmed with user)

1. **Build the CLI verbs now**, wired against existing interfaces, TDD-tested with the fake `storage.Store`. Concrete DO Spaces client + timer stay in Phase 6.
2. **Wire the full Postgres-backed async Manager** into `serve.go`: use `jobs.NewPostgresStore` when a DB is configured (else `MemStore`), register the backup/restore handlers, so backup/restore flow through the ledger end-to-end. (`server.Run` already calls `ResetOrphans` + `Run`; cmd only needs to register kinds.)
3. **Audit actor = server-stamped, never client-supplied.** The server overwrites `params.actor` with the authenticated `identity.Principal` before `Submit`. This keeps identity authoritative (a client can't claim to be someone else), loses no `Tenant`/`Type` (unlike reading the ledger's email-only `Job.Actor` string), and needs no Handler/Job API change or migration. The CLI sends `{}` / `{"object_key": ...}` and never sends an actor.

## What already exists (do NOT rebuild)

- `internal/backup`: `Service{Dumper, Store, Key, Recorder, DSN, NowFunc}`, `Backup`/`Restore`/`Register`, `DeriveKey`, kind/action constants, params/result types. Tests green.
- `internal/jobs`: `Manager` (Register/Submit/Get/List/ResetOrphans/RunOnce/Run), `NewMemStore`, **`NewPostgresStore(db, tenantID)`** (migration `0005_jobs.sql`: RLS, idempotency, SKIP LOCKED, orphan reset).
- `internal/server/jobs.go`: admin-gated `POST /api/jobs` (`{kind, idempotency_key, params}` → `{job, created}`; unknown kind → 400), `GET /api/jobs`, `GET /api/jobs/{id}`.
- `cmd/kura/jobs_cmd.go`: `fetchJob`, `waitForJob` (`jobsPollInterval` var), `isTerminalStatus`, `defaultWaitTimeout`. Cobra; commands registered in `commands.go` `newRootCmd()`. CLI test harness: `runRoot`/`runRootStdin`, tempdir HOME/XDG + seeded token cache (`ingest_test.go`).
- No new migration needed: backup metadata is covered by the audit log (`backup.created`/`backup.restored`) + `storage.List`.

## Implementation — tracked as child tasks under fvbRA

Import the YAML block below with `job import <thisfile> --parent fvbRA` (validate first with `--dry-run`). Each leaf is built strict red→green (write failing tests, verify fail, implement). The existing fvbRA criteria (eMs/OSH/yYc/E7K) stay as the acceptance gates and get marked `passed` as the corresponding leaf lands.

```yaml
tasks:
  - title: "Server stamps the authenticated principal into job params"
    ref: actor-stamp
    labels: [jobs, server, security, tdd]
    desc: |
      In submitJobBinding (internal/server/jobs.go), before calling Manager.Submit, overwrite the params' actor field with the server-authenticated identity.Principal (full Type/ID/Email/Tenant). Identity must be asserted by the server that authenticated the request, never trusted from the client payload. The backup/restore handlers read params.actor as a full Principal, so this makes the backup.created/backup.restored audit events name the real caller without changing the Handler/Job contract or the ledger schema. Generic across all job kinds: a kind whose params have no actor field simply gains one.
    criteria:
      - "a client-supplied params.actor is overwritten by the authenticated principal"
      - "params with no actor object get the authenticated principal injected"
      - "the full Principal (incl. Tenant) is preserved, not just the email"
  - title: "Wire the Postgres-backed async jobs Manager into kura serve"
    ref: serve-wiring
    labels: [cli, jobs, tdd]
    desc: |
      Refactor buildStores (cmd/kura/serve.go) to also return the *sql.DB pool (nil on the in-memory path). Add buildJobsManager(getenv, recorder, pool) that builds the Manager over jobs.NewPostgresStore(pool, tenantID) when a DB is configured, else NewMemStore. It constructs backup.Service (PGDumper, the backups Store, key via secrets.Manager.Get(BACKUP_ENCRYPTION_KEY)→DeriveKey, recorder, DSN) and calls svc.Register(mgr) ONLY when a backups Store is obtainable. No concrete Store exists in production yet, so prod registers no backup/restore kinds and POST /api/jobs{kind:backup} returns a clear 400 — intended graceful degradation until Phase 6. Replace the Jobs literal at serve.go:258. server.Run already handles ResetOrphans + Run.
    criteria:
      - "with a DB configured, the jobs Manager uses the Postgres store"
      - "given a backups Store + secrets backend, mgr.Kinds() includes backup and restore"
      - "with no backups Store, serveConfig succeeds and registers no backup/restore kinds"
  - title: "kura backup CLI verb"
    ref: cli-backup
    labels: [cli, tdd]
    desc: |
      New cmd/kura/backup.go (+ test). Thin verb: resolveServerFromFlags; submit POST /api/jobs with kind=backup via a shared submitJob helper that decodes submitJobResponse to get the job id; flags --wait (reuse waitForJob), --timeout, --idempotency-key (default: random per run, since backups aren't idempotent); render the BackupResult (object_key/bytes/sha256) via clio (--json supported). Guard --local with a clear Phase-6 "needs on-box storage backend" error (no concrete Store in the CLI yet). Register in commands.go. Satisfies fvbRA criterion eMs.
    blockedBy: [actor-stamp]
  - title: "kura restore CLI verb"
    ref: cli-restore
    labels: [cli, tdd]
    desc: |
      New cmd/kura/restore.go (+ test). kura restore <object-key> (positional, required). Destructive, so require --confirm (matches the global flag contract) before submitting kind=restore. Default --idempotency-key derived from the object key so an accidental double-submit re-attaches rather than re-running; overridable. --wait/--timeout/--json like backup; --local guarded. Reuse the shared submitJob helper. Satisfies fvbRA criterion yYc.
    blockedBy: [actor-stamp]
  - title: "End-to-end async backup/restore round-trip test (audited + on the ledger)"
    ref: e2e
    labels: [jobs, testing, tdd]
    desc: |
      The criteria-proving test (internal/server, full server.Config with a fake append-only storage.Store + fake secrets + registered backup.Service). Admin POST /api/jobs{kind:backup} → drive RunOnce → GET /api/jobs/{id} shows succeeded with object_key/sha256 in the ledger (E7K half 1); assert a backup.created audit event names the authenticated principal (E7K half 2, proving the actor-stamp). Restore leg: submit kind=restore → succeeds → backup.restored audited. Non-admin submit → 403. Confirms criteria OSH (key distinct/from secrets, already true in internal/backup) and E7K.
    blockedBy: [actor-stamp, serve-wiring, cli-backup, cli-restore]
  - title: "Document kura backup / kura restore"
    ref: docs
    labels: [docs]
    desc: |
      Update docs/content/docs/machine-interface/cli-jobs.md (the two verbs are now built, not "next phase"). Add a cli-backup-restore reference page (flags, wire shapes, admin-only gating, encrypted/append-only/distinct-key guarantees, that they appear in kura jobs list, the Phase-6 --local stub) and link it from machine-interface/_index.md. Add a one-line cross-link in concepts/storage.md. Add the verbs to any CLI verb table in README.md. CLAUDE.md mandates docs stay current.
    blockedBy: [cli-backup, cli-restore]
```

## Files

**New:** `cmd/kura/backup.go` (+ `backup_test.go`), `cmd/kura/restore.go` (+ `restore_test.go`), a shared `submitJob` helper (in `backup.go` or `cmd/kura/jobs_submit.go`), an e2e test (`internal/server/jobs_backup_test.go`), new doc page `docs/content/docs/machine-interface/cli-backup-restore.md`.

**Modified:** `internal/server/jobs.go` (stamp principal into params + regression test in `jobs_test.go`), `cmd/kura/serve.go` (`buildStores` returns pool; add `buildJobsManager`; replace `Jobs:` literal; update comment block 251-257), `cmd/kura/commands.go` (register both verbs), `docs/content/docs/machine-interface/{cli-jobs.md,_index.md}`, `docs/content/docs/concepts/storage.md`, `README.md`.

**Unchanged (confirmed done):** `internal/backup/*`, `internal/jobs/*` (API), the `POST/GET /api/jobs` endpoints, `internal/storage/*`, `internal/secrets/*`, migrations.

## Risks / edge cases

- **No concrete Store in prod** → backup/restore kinds unregistered → `POST /api/jobs{kind:backup}` returns 400 "unknown job kind". Intended; document the Phase-6 dependency loudly.
- **Admin-gating**: backup/restore require an admin principal (the `POST /api/jobs` route is admin-only); a user/auditor token gets 403. Asserted in the e2e test, documented.
- **Restore is destructive** → `--confirm` required.
- **`buildStores` signature change** ripples to its one caller (`serveConfig`); existing Postgres integration tests assert store types, unaffected by the added pool return.
- **CLI test timing**: use the fake-server script + dialed-down `jobsPollInterval`; the real worker is exercised deterministically via `RunOnce` in the e2e test.

## Verification

- Per leaf: `go test ./cmd/kura/...`, `go test ./internal/server/...`, `go test ./internal/backup/...`; `gofmt`/`go vet ./...` (+ the architecture test that keeps `cmd` thin).
- Integration (real test Postgres, single boot per [[feedback_integration_test_runs]]): `KURA_TEST_DATABASE_URL=… go test ./cmd/kura/... ./internal/backup/...` for the Postgres-jobs path + the real round-trip.
- Manual: `go run ./cmd/kura backup --local` shows the Phase-6 guard; against a dev `kura serve` with no Store, `kura backup` shows a clean 400.
- Close-out: mark fvbRA criteria eMs/OSH/yYc/E7K `passed` as their leaves land; the import nests the breakdown under fvbRA so it auto-closes (which auto-closes Phase 3 `0gr2v` — confirm scope at close).
