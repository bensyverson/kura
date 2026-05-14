---
title: The enforcement gate
weight: 10
---

"The core is the gate" — made concrete. The `gate` package ties the
enforcement subsystems into the **single entrypoint every adapter calls**:

```
authenticate → authorize → access → mask → audit
```

The HTTP API, the CLI's `--local` path, the local dashboard, and the MCP
server all go through the gate and nothing else. None of them may
reconstruct any of these steps themselves — that is the whole point.

## Three verbs: `Access`, `List`, and `Admin`

The gate exposes exactly three entrypoints, and they are the same welded
chain in three shapes:

- **`Access`** reads one record. The authorization step asks the `read`
  question; the `Fetcher` returns one record's fields.
- **`List`** reads a bounded page of an entity's records. The
  authorization step asks the `list` question; the `ListFetcher` returns
  a page; every record in the page is masked; and the whole page is **one
  audit event** — a list happened, on the entity, touching no single
  record id.
- **`Admin`** runs an administrative operation — managing the
  authorized-user list, assigning roles, reading effective policy. It
  touches no manifest entity and no PII, so it is the chain *with the
  data steps absent*: authenticate → authorize → run the operation →
  audit. The operation is a caller-supplied callback the gate runs only
  after authorization passes, exactly as `Access` owns its `Fetcher`.
  `AdminManage` (mutations) needs the admin role; `AdminReview` (reads —
  effective policy, IdP mismatches) is access-review work the auditor may
  also do.

`List` is **bounded by construction**. A request with no limit gets the
default page size; one asking for more than the ceiling is clamped to it.
The gate clamps the page *before* the fetch runs, so an adapter cannot
dump an unbounded result set no matter what it asks for. The effective
limit and offset come back in the result, so a caller can page without
guessing what bounds it got. The default and ceiling page sizes are
`DefaultPageSize` and `MaxPageSize` in the `gate` package.

The effective policy the gate enforces is readable through
`Gate.Policy()` — read-only, because policy authoring stays a repo/PR
activity, never a server write path.

## The chain

| Step | What happens |
| --- | --- |
| **authenticate** | The request's token is resolved to a principal. A bad token is recorded as a failed authentication and the request stops. |
| **authorize** | Cedar decides the request against the principal's roles and the **PII categories the manifest declares** for the entity — categories, never column names. A denied request is recorded and stops here. |
| **access** | Only now is the caller-supplied `Fetcher` (or `ListFetcher`) invoked to read the data. For a list, the gate has already clamped the page bounds. |
| **mask** | The data is re-scanned for PII (catching detector drift since ingestion) and every span whose category the authorization decision did not make visible is redacted. A list masks every record in the page. |
| **audit** | The access is recorded — once per `Access`, and once per `List` page. |

## Welded shut by construction, not convention

The criterion for the gate is that **skipping a step is impossible by
construction**. Four properties enforce that:

- **Three verbs, no subsets.** `Gate` exposes only `Access`, `List`, and
  `Admin`. There is no public method that performs a subset — no
  standalone "authorize" or "mask" an adapter could call instead.

- **The Fetcher is not an escape hatch.** The data read is caller-supplied,
  but the gate owns *when* it runs (only after authorization passes) and
  *what happens to its output* (masked and audited before return). A denied
  request never reaches the Fetcher. The same holds for a `List`'s
  `ListFetcher` — and the gate clamps its page bounds besides.

- **Masking is identical for every caller** because it happens here. The
  redaction logic is not reachable or overridable by an adapter, so the API,
  CLI, and MCP server cannot produce different masked output for the same
  request.

- **Fail closed on audit.** A step that cannot be audited fails the whole
  request — an access Kura cannot record is one it does not return.

## Drift safety

Authorization reasons about the PII categories the **manifest declares**.
Masking re-scans the **actual data** at access time. If the detector finds a
category the manifest never declared — drift since ingestion — the
authorization decision never classified it, so it is not visible, so it is
redacted. The safe default falls out of the design rather than being a
special case.
