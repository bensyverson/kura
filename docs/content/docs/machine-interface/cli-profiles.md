---
title: CLI profiles — the --client switch
weight: 4
---

A consultant's laptop addresses **N** client servers. The `kura --client <name>` switch resolves a friendly name to the right `kura serve` endpoint without any hand-edited URL juggling.

Profiles live at `~/.config/kura/config.json` (or the OS equivalent). They store **endpoints**, never credentials. Tokens are short-lived and come from `kura login` — they live in a separate, owner-only credential cache and are never written into a profile.

## The verbs

```sh
kura profile list
kura profile add    --name <n> --endpoint <URL>
kura profile remove --name <n>
```

`profile list` reports the empty state explicitly when no profiles are configured, so an agent doesn't have to grep the filesystem to learn it. `--json` emits the stable `{clients: {name: {endpoint: ...}}}` schema.

`profile add` refuses to overwrite an existing client (exit 5 conflict) — replacing an endpoint is `remove` then `add`, so the previous value is never silently lost.

`profile remove` on an unknown name surfaces the loader's enumerating NotFound error (exit 4), with the menu of configured clients inline. The same enumerating message the loader emits when `--client <name>` references an unknown name.

## How --client resolves

Every remote verb (`whoami`, `status`, future data/admin verbs) reads the server URL by the same precedence — pinned across the codebase in `resolveServer`:

1. `--server <URL>` — explicit override;
2. `--client <name>` — profile lookup;
3. the server stored in the cached credential from the most recent `kura login`.

So `kura --client acme whoami` looks up "acme" in `~/.config/kura/config.json`, takes that endpoint, and hits it with the cached token. The `--client` flag is **global** (a persistent root flag), so it composes with every verb without per-command plumbing.

## The no-credentials rule

The profile is *only* ever the pair `(name, endpoint)`. The defense is structural:

- **Writer side.** `kura profile add` registers exactly two flags — `--name` and `--endpoint`. There is no `--token` flag, so a credential cannot enter the file through this command. `TestProfileAddCommandHasNoCredentialFlags` pins this — adding a credential-shaped flag fails CI.
- **Reader side.** `loadProfilesFrom` walks each client and rejects any field other than `endpoint`. A hand-edited config that drops in `"token": "leaked"` is refused with `profiles: client "<n>" has a "token" field — credentials never live in profiles (tokens come from kura login)`. `TestLoadProfilesRejectsCredentialsField` pins this.
- **On-disk.** `TestProfileAddDoesNotWriteCredentialField` reads the post-add config back and asserts no credential-shaped string ever appears.

This trio means it is *structurally* impossible to round-trip a token through a profile — by design, per the doc-03 threat model.
