---
title: CLI users & roles
weight: 5
---

The authorized-user list and the role assignments on it are managed from the CLI, not the dashboard or a database console. Every mutation lands on the same gated admin API `kura serve` exposes, so the operation is authorized by Cedar, audited by `audit.Recorder`, and tenant-scoped by row-level security in one shot.

The verbs in this page are all **remote-only**: they talk to a `kura serve` over HTTP with the cached bearer token. The `--local` break-glass mode does not apply to admin mutations — there is no out-of-band path that bypasses the audit trail.

## The verbs

```sh
kura user list
kura user add <email>...
kura user show <email>
kura user deactivate <email>...
kura role assign --role <role>... <email>...
kura role revoke --role <role>... <email>...
kura role list
```

## Variadic, atomic, idempotent

The mutating verbs all hold the same three properties, by design:

- **Variadic.** `kura user add a@x b@x c@x` adds three users in one invocation. `kura role assign --role admin --role auditor alice bob` grants two roles to two users in one invocation. There is no shell loop to script.
- **Atomic at the per-call unit.** Each individual mutation runs in one transaction at the data layer — `AssignRoles(email, roles…)` either commits the whole named role set for that user, or none of it. The CLI fans the variadic input out to one server call per user; the server runs each call as one atomic transaction.
- **Idempotent.** Re-running the same command is a no-op. `user add` of an already-listed user keeps their roles untouched (`ON CONFLICT DO NOTHING`). `role assign` of an already-held role does not duplicate. `role revoke` of a role the user does not hold deletes nothing. `user deactivate` of an already-roleless user is a no-op.

There is one place atomicity does *not* extend, by design: across the variadic batch. If `kura user add a b c` finds `c` is malformed and the server rejects it after `a` and `b` are already added, those two stay. The remedy is the natural property — re-running is safe. The CLI surfaces the first error verbatim, with the per-call exit code from the taxonomy.

## Teaching acks

Every successful mutation prints a one-line "next move" hint, so an agent that is moving through the access-control workflow does not have to guess which verb comes next:

- `kura user add alice@x bob@x` →
  `Added 2 user(s): alice@x, bob@x.`
  `Next: \`kura role assign --role <role> alice@x bob@x\` to grant access.`
- `kura role assign --role auditor alice@x` →
  `Granted role(s) auditor on 1 user(s): alice@x.`
  `Next: \`kura user list\` to confirm the new role set.`
- `kura user deactivate alice@x` →
  `Deactivated 1 user(s): alice@x.`
  `Next: \`kura user list\` to confirm, or \`kura role assign --role <role> <email>\` to restore access.`

These follow the same agent-facing contract as the rest of the CLI: the success path teaches; the failure path classifies (see [CLI output & errors](../cli-output)).

## Deactivate is not delete

`kura user deactivate <email>` atomically revokes **every** role the user holds, leaving the user on the authorized list. Deactivation is auditable history, not a delete — there is no `kura user remove`. The audit log retains the deactivation event, the on-list record stays, and the next role decision the gate makes for that principal resolves to no access.

To re-grant access, run `kura role assign --role <role> <email>`. To re-add the same email after deactivation, `kura user add` is a no-op (they are still on the list).

## `kura role list` is read-only

The effective authorization policy is rendered from the gate's IR (`internal/cedar`). The CLI is a presentation layer over it — there is no `kura role create` or `kura grant add` verb. Policy authoring is a repo activity: a PR against the cedar package, reviewed and merged. This keeps every change to the rule set under the same review process as code, and the running deployment carries one canonical policy rather than a runtime overlay that diverges from the repo.

`kura role list` shows the role table (name plus description, if any) and the role→entity:action grants, including the per-grant `VisiblePII` set when a grant exposes plaintext PII categories.

## Output and errors

Every verb on this page follows the shared contract from [CLI output & errors](../cli-output):

- `--json` emits the stable schema; the default is dense Markdown.
- Errors are `*clio.Error` with a `<verb>: ` prefix, a taxonomy `Kind`, and an exit code.
  - `user show <unknown-email>` → `KindNotFound` (exit 4), with a `kura user list` hint inline.
  - `user add` / `user deactivate` with no positional args → `KindUsage` (exit 2).
  - `role assign` / `role revoke` without `--role` → `KindUsage` (exit 2).
  - Server 401/403 → `KindAuth` (exit 3); server 5xx → `KindTransient` (exit 6).
