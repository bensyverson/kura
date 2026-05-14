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
server all go through `Gate.Access` and nothing else. None of them may
reconstruct any of these steps themselves — that is the whole point.

## The chain

| Step | What happens |
| --- | --- |
| **authenticate** | The request's token is resolved to a principal. A bad token is recorded as a failed authentication and the request stops. |
| **authorize** | Cedar decides the request against the principal's roles and the **PII categories the manifest declares** for the entity — categories, never column names. A denied request is recorded and stops here. |
| **access** | Only now is the caller-supplied `Fetcher` invoked to read the data. |
| **mask** | The data is re-scanned for PII (catching detector drift since ingestion) and every span whose category the authorization decision did not make visible is redacted. |
| **audit** | The access is recorded. |

## Welded shut by construction, not convention

The criterion for the gate is that **skipping a step is impossible by
construction**. Four properties enforce that:

- **One verb.** `Gate` exposes only `Access`. There is no public method that
  performs a subset — no standalone "authorize" or "mask" an adapter could
  call instead.

- **The Fetcher is not an escape hatch.** The data read is caller-supplied,
  but the gate owns *when* it runs (only after authorization passes) and
  *what happens to its output* (masked and audited before return). A denied
  request never reaches the Fetcher.

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
