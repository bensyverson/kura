---
title: CLI smoke verb — kura smoke
weight: 12
---

`kura smoke` runs an end-to-end health suite against a running `kura serve`, addressed by URL. It is one artifact with three uses:

- **CI's ephemeral deploy** — the post-deploy gate that decides whether a build is promotable.
- **The staging environment** — a quick "is staging actually working?" probe.
- **The provisioning agent's Definition of Done** — the per-engagement check that a freshly stood-up client system is live and enforcing the gate.

Because the same suite must run in all three places, it speaks **only to the public HTTP surface** and needs **no credential**. One of its checks deliberately confirms the gate rejects an unauthenticated request — so "no credential" is a feature, not a gap.

## The verb

```sh
kura smoke --server <url>
kura smoke --client <profile>
kura smoke                       # uses the cached login server
```

Server resolution follows the same precedence as every other verb: `--server` wins, then `--client`, then the cached login.

## What it checks

The suite probes the open surface of the server:

| Check           | Probe                                  | Pass condition |
| --------------- | -------------------------------------- | -------------- |
| `reachable`     | `GET /healthz`                         | `200`          |
| `ready`         | `GET /readyz`                          | `200`          |
| `auth-enforced` | `GET /api/_smoke_auth_check` (no token)| `401`          |

The `auth-enforced` check is the security-relevant one: an unauthenticated `/api/` request must be rejected with `401`. A `200` there means the gate is not enforced, and the run fails.

Deeper flow checks — the audit, PII-detection, and LLM-gateway end-to-end flows — are added to the suite as the server grows the smoke hooks they need. The suite is defined once in `internal/smoke` and runs identically wherever it is invoked.

## Output

Markdown by default — one line per check, plus the overall outcome:

```text
# smoke https://kura.client.example

- [PASS] reachable — GET /healthz answers 200
- [PASS] ready — GET /readyz answers 200
- [PASS] auth-enforced — an unauthenticated /api/ request is rejected with 401

outcome: pass
```

`--json` emits the structured report for a parser:

```json
{
  "base_url": "https://kura.client.example",
  "outcome": "pass",
  "results": [
    { "name": "reachable", "desc": "GET /healthz answers 200", "passed": true },
    { "name": "ready", "desc": "GET /readyz answers 200", "passed": true },
    { "name": "auth-enforced", "desc": "an unauthenticated /api/ request is rejected with 401", "passed": true }
  ]
}
```

`outcome` is one of `pass`, `fail`, or `unreachable`. The per-check report is printed for **every** outcome, including failures, so the caller always sees which check failed before reading the exit code.

## Exit codes

The outcome maps onto three points of the [exit-code taxonomy](cli-output#exit-code-taxonomy), because each demands a different next action:

| Exit | Outcome       | Meaning                                                              | Agent action |
| ---- | ------------- | ------------------------------------------------------------------- | ------------ |
| `0`  | `pass`        | Every check passed.                                                 | Done.        |
| `6`  | `unreachable` | The server could not be contacted at all — it may not be up yet.    | Retry.       |
| `7`  | `fail`        | The server answered, but a check failed — the deployment is broken. | Escalate.    |

The split between `6` and `7` is the point: "the server isn't up yet" (transient, retry) and "the server is up but broken" (escalate, do not retry) are different problems, and an automated caller must distinguish them without scraping prose.

On an `unreachable` outcome the suite **short-circuits**: once a probe reports a transport-level failure, the remaining checks would only produce noise, so the report holds the results gathered so far.

## Where the contract is enforced

- **The suite**: `internal/smoke/` — the checks, the three-valued outcome, and the runner. This is where logic lives.
- **The CLI**: `cmd/kura/smoke.go` is wiring — resolve the server, run the suite, render the report, map the outcome to a `clio` error so the exit code follows the taxonomy.
