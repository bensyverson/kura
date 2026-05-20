---
title: Local development
weight: 8
---

Stand up a complete, populated Kura on your own machine — Postgres, the
API server, seeded users and records, and the dashboard — with one
command. It exists to smoke-test the whole stack end to end, especially
the dashboard pages, against real data.

```bash
scripts/dev-instance.sh
```

That boots everything, ingests sample records, prints the same data masked
two ways (as an admin and as a plain user), and opens the dashboard.
Press **Ctrl-C** to tear it all down. It is idempotent — safe to re-run —
and it caches its credentials under an isolated config home, so it never
touches your real `kura login`.

## What it composes

The one-command script ([`scripts/dev-instance.sh`](https://github.com/bensyverson/kura))
wires together pieces you can also run by hand:

1. **Postgres** — `scripts/test-db.sh` brings up the containerized,
   TLS-enabled, pgaudit-bundled database the [data layer](../concepts/database)
   expects. (Needs a container runtime — we use [Colima](https://github.com/abiosoft/colima).)
2. **A stub PII detector** — `kura dev pii-detector`. The gate scans every
   ingest and every read through the [PII detector](../concepts/pii); this
   stub speaks the same contract offline, so you need no model service.
3. **`kura serve`** — wired to that DB, the dev [schema manifest](../concepts/schema-manifest)
   (`scripts/dev/manifest.json`), and a signing secret. It runs fully
   offline: `KURA_IDP=google` supplies the sign-in wiring from string
   credentials (it never dials out at startup), and `KURA_DIRECTORY=none`
   turns off IdP-mismatch detection so nothing reaches a real directory.
4. **Seeded users and roles** — `kura dev seed-users` writes the first
   admin and user straight into the store. A fresh deployment has no admin,
   and every admin API mutation needs the admin role — so the first role
   assignment cannot go through the API. This is the bootstrap that breaks
   that chicken-and-egg, the same way a production deployment seeds its
   first admin.
5. **A cached token** — `kura dev token` mints a signed token from the
   signing secret without the browser OAuth flow, and `--save` caches it so
   `kura ingest`, `kura query`, and `kura dashboard` are signed in.
6. **Seeded records** — through the real [ingestion API](../concepts/ingestion)
   (see the seed path below).

## The `kura dev` helpers

These are hidden, development-only subcommands — excluded from `kura
agent-context` and from a deployed surface. None grants privilege beyond
what the holder of the signing secret or the database credentials already
has; they package those capabilities for local use.

| Command | What it does |
| --- | --- |
| `kura dev token` | Mint a signed token from `KURA_SIGNING_SECRET`, headlessly. The principal comes from the flags; `--save --server <url>` caches it like `kura login` would. |
| `kura dev pii-detector` | Run a stub PII detection service (the regex `PatternDetector`) over the real detect contract, for offline scanning. |
| `kura dev seed-users` | Bootstrap users and roles directly into the configured store — the no-admin-yet bootstrap. Reads the same `KURA_DATABASE_URL` / `KURA_DB_TENANT_ID` as `kura serve`. |

## The seed path

Records get into Kura through the same manifest-driven
[ingestion](../concepts/ingestion) path everything else uses — there is no
special test-only write path. To seed data into a running serve + Postgres:

1. Sign in (or, headless, `kura dev token --type admin --email you@example
   --tenant example --save --server <url>`). The principal must hold a role
   that the policy grants `create` — `admin` or `user`.
2. Ingest a JSON object or array per entity:

   ```bash
   kura ingest customer --file scripts/dev/seed/customer.json --server <url>
   kura ingest order    --file scripts/dev/seed/order.json    --server <url>
   ```

Each record is authorized, validated against the manifest, PII-scanned,
classified for at-rest encryption, written, and audited — the full gate.
The sample data in `scripts/dev/seed/` is shaped to exercise that: the
`customer` entity carries an email, a phone, an SSN (the high-sensitivity
`account_number` category), and a free-text `notes` field.

## Seeing masking per principal

Read the seeded data back as two different principals and the
[policy](../concepts/policy) shows its teeth:

```text
--- as admin: high-sensitivity (ssn) visible ---
- … ssn: 123-45-6789

--- as user: high-sensitivity (ssn) masked ---
- … ssn: [redacted]
```

The admin role sees every PII category; the user role sees everything
except the high-sensitivity ones, which stay masked. Same record, same
endpoint — the gate masks per the caller's policy. The SSN is also stored
**encrypted** at rest, because the manifest declares it a high-sensitivity
category.
