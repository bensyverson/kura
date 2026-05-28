---
title: CLI backup & restore — kura backup, kura restore
weight: 9
---

`kura backup` and `kura restore` drive the [independent logical-backup tier](../../concepts/storage/): the compromise-resilient copy that earns the security improvement over bare managed Postgres. Both are **thin presenters** — the orchestration (dump, encrypt, append-only write; and its reverse) lives in the core and runs server-side as an [async job](../cli-jobs/). The CLI submits the job and, optionally, waits on it.

```sh
kura backup [--wait] [--timeout DUR] [--idempotency-key KEY]
kura restore <object-key> --confirm [--wait] [--timeout DUR] [--idempotency-key KEY]
```

Submitting either is an **`AdminManage`** operation — admin only — and every submission is audited and lands on the jobs ledger, so `kura jobs list` / `kura jobs get` see them like any other job.

## `kura backup` — take an encrypted backup

`kura backup` submits a `backup` job. Server-side, the core dumps the database (`pg_dump`, custom format), encrypts the dump with **AES-256-GCM** under a key sourced from the secrets manager (`BACKUP_ENCRYPTION_KEY`, **distinct** from the runtime `FIELD_ENCRYPTION_KEY`), and writes the ciphertext to the separate-region BACKUPS bucket through the **append-only** role. A `backup.created` audit event records the action against the new object key.

The verb takes no arguments. Without `--wait` it prints the submitted job (id and `pending` status) and returns immediately; the backup proceeds server-side.

```sh
kura backup --wait
```

With `--wait` it polls the ledger until the job is terminal and prints the result: the `object_key`, the encrypted size in `bytes`, and the `sha256` of the ciphertext.

The **idempotency key** defaults to a fresh random value per invocation — backups are not idempotent on any natural attribute, so each run is a new backup. Pass `--idempotency-key` to re-attach to an in-flight backup (e.g. after a dropped connection) instead of starting another.

## `kura restore` — restore from a backup object

`kura restore <object-key>` submits a `restore` job for a named backup object (the `object_key` a prior `kura backup` reported, or one listed on the ledger). Server-side the core reads the object, decrypts it with the same secrets-sourced key, and runs `pg_restore` into the target; a `backup.restored` audit event records it.

Restore **overwrites the target database**, so it is destructive and requires `--confirm`:

```sh
kura restore backup-20260528T140000.000000000Z.dump.enc --confirm --wait
```

The **idempotency key** defaults to one derived from the object key (`restore-<object-key>`), so an accidental double-submit re-attaches to the in-flight restore rather than running it twice. Override with `--idempotency-key`.

## Identity is server-stamped

Neither verb sends an actor. The server stamps the **authenticated principal** (from the bearer token) into the job before it runs, so the `backup.created` / `backup.restored` audit events name the real caller — a client cannot attribute the action to someone else.

## `--local` is a Phase 6 break-glass stub

The global `--local` flag (break-glass on-box execution, the form the scheduled backup timer will use) needs the on-box object-store backend, which lands with the [deployment baseline](../../concepts/storage/). Until then, `kura backup --local` / `kura restore --local` fail with a clear message; run against a remote `kura serve`.

> [!NOTE]
> A `kura serve` with no backups store configured does not register the `backup`/`restore` job kinds, so a submission answers `400 unknown job kind`. The concrete object-store client is provisioned in the deployment baseline; until then these verbs are exercised against a configured store in tests.
