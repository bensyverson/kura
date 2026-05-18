---
title: CLI data verbs — query & show
weight: 6
---

`kura query` and `kura show` are the CLI's window onto the records the server stores. They are manifest-driven: the entity name is just an argument, and the verbs work for any entity the manifest declares — there is no per-entity wiring in the CLI.

Both verbs are **remote-only**. They GET the server's masked data routes (`GET /api/{entity}`, `GET /api/{entity}/{id}`) over the cached bearer token; access-time masking and page bounds are the server's job, never the CLI's.

## The verbs

```sh
kura query <entity> [--limit N] [--offset M]
kura show  <entity> <id>
```

## Bounded by default

`kura query` is bounded by the gate, not by the CLI:

- No `--limit` → server applies `gate.DefaultPageSize` (50 today).
- `--limit N` ≤ `gate.MaxPageSize` (200 today) → server honors it.
- `--limit N` > `MaxPageSize` → server silently caps at `MaxPageSize`.
- Negative `--offset` → server floors at zero.

The response echoes the **effective** `limit` and `offset` back, so an agent can see what bound the gate actually applied rather than what was asked for. The Markdown view prints them inline; the `--json` view exposes the same numeric fields.

This is deliberate: the CLI does not try to fight the gate's bounds. There is no `--all` flag, no recursive page-walking helper. An agent that needs more than `MaxPageSize` records pages by repeatedly bumping `--offset`.

## Masked by the server, surfaced unchanged

Every field value the CLI prints has already been masked per the caller's policy by the server. The CLI never:

- replaces masked values with plaintext,
- adds masking on top (the server is the source of truth),
- or filters records out of a page.

If the agent's policy hides every field on an entity, `kura show` prints an explicit "no fields visible" line rather than an empty record — the empty state is informative, not silent.

## No relationship traversal

The manifest declares relationships between entities (`Entity.Relationships`, kind `one` / `many`, target entity), but **Kura does not traverse them**. By design:

- `kura show <entity> <id>` returns the single record's fields, flat.
- There is no tree-of-records shape, no implicit FK following, no joined view.
- Manifest relationships stay declarative metadata — useful to the dashboard, the MCP, and any other surface that wants to describe the schema, but not load-bearing in the data fetch path.

The stance is that Kura is the access and storage layer; clients orchestrate. If you want a patient's visits, you make a second call (`kura query visit` with a filter once filtering ships). That keeps Kura unopinionated about the *shape* of the data — clients pick whether FKs live in `_id` fields, separate join tables, denormalized JSON, or anywhere else. Kura authorizes, masks, audits, paginates; the caller composes.

## Output and errors

Both verbs follow the shared contract from [CLI output & errors](../cli-output):

- `--json` emits the stable schema (a `{records, limit, offset}` page for query; `{entity, id, fields}` for show). Markdown is the default.
- `KindUsage` (exit 2) when the positional shape is wrong (no entity, or `show` missing the id).
- `KindNotFound` (exit 4) when `kura show` asks for an id the server does not have.
- `KindAuth` (exit 3) on 401/403; `KindTransient` (exit 6) on 5xx; everything else falls through `classifyHTTPStatus` to `KindInternal`.
