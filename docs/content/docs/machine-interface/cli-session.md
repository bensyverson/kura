---
title: CLI session — status, login, logout, whoami
weight: 3
---

The four verbs an agent uses to orient itself and manage its session with a `kura serve`. Run `kura status` first, every session.

## `kura status` — the session opener

`kura status` is the **first call** an agent makes in a session. Same shape as `job status`: identity check plus landscape briefing in one round-trip. It answers the four orienting questions in one document:

- **server** — the URL the agent is talking to;
- **identity** — the principal the server resolves the cached token to (via `GET /api/whoami`);
- **tier** — the deployment tier the server is running on (placeholder until Phase 6);
- **anomalies** — audit anomalies needing attention (placeholder until the audit-anomalies surface lands).

Tier and anomalies are **present in the JSON document on purpose**, even while their values are placeholders, so an agent parses one stable schema across phases — the values become real without a schema change.

```sh
kura status                  # dense Markdown briefing
kura status --json           # the stable schema
```

The Markdown view ends with a "what's next" hint pointing at `kura --help` and `kura agent-context` — the same acks-teach pattern every kura verb follows.

## `kura login` — OAuth handoff, short-lived token

`kura login --server <URL>` runs the loopback-handoff OAuth flow against the remote server and caches the minted token. The flow:

1. The CLI binds a loopback listener on `127.0.0.1:<random>` and generates a cryptographic state value.
2. It opens the browser to `<server>/oauth/login?redirect=<loopback>` and waits.
3. The browser completes the IdP sign-in, the server delivers the token back to the loopback, the CLI matches the state, and the token is written to the OS-conventional config dir (`~/Library/Application Support/kura/credentials.json` on macOS, `$XDG_CONFIG_HOME/kura/credentials.json` on Linux), owner-readable only.

A callback bearing a state value that doesn't match the one the CLI generated is **rejected** — the loopback listener cannot be tricked into accepting an injected token.

The token is **short-lived** by design (the design-guidelines rule "no long-lived secrets on disk"). When it expires, the next remote command surfaces an Auth error and the agent re-runs `kura login`.

## `kura logout` — clear the cached token

`kura logout` deletes the cached credential file. It is **idempotent** — an empty cache is a clean no-op on stdout, not an error — so an agent can call it without first checking whether a credential exists.

```sh
kura logout
# → "Signed out. Cached credential removed."
# or, on an already-empty cache:
# → "Signed out. (no cached credential)"
```

After logout, the next remote command falls through to:

```
login: no cached credential (run `kura login`): ...
```

…which is the agent's cue to start the OAuth flow again.

## `kura whoami` — the minimal identity read

`kura whoami` is the smallest possible self-identity check. It is `kura status` minus the briefing — useful when the agent only wants to know "who does the server see me as right now?" without rendering the rest of the document.

It also supports `--local` for the **break-glass** path: when the server itself is down, `kura whoami --local --as <email>` resolves the principal directly through `identity.TenantTrust` — the same code the server runs on the OAuth callback. `--local` is documented in [identity](/docs/concepts/identity) as an incident-response path, not a default.

## Identity precedence

Every session command resolves the server URL by the same precedence:

1. `--server <URL>` — explicit override;
2. `--client <name>` — named profile lookup in `~/.config/kura/config.json`;
3. the server stored in the cached credential from the most recent `kura login`.

If none of the three resolves, the error names all three fixes in one line — the agent gets the menu without scraping `--help`.
