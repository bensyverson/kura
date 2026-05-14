# Kura — Full Build Plan

This is the hierarchical build plan for **Kura**, an open-source, secure-data-store
template for SMB consulting engagements. It is written in `job import` grammar — the
first fenced YAML block below is the importable plan. Everything outside that block is
context for human readers.

## What Kura is

A single open-source Go binary, `kura`, that provisions and operates a secure,
audited data store for centralizing client PII. It has four faces over one core:

- **`kura serve`** — the remote HTTP API server (the only public surface).
- **`kura <verb>`** — the CLI: a local agent's HTTP client to a remote server
  (`--local` is break-glass only).
- **`kura dashboard`** — a local web app, itself an HTTP client of the remote API.
- **`kura mcp`** — an MCP server (local proxy by default; remote-served for a
  client's post-handoff agents).

All four are thin adapters over `internal/` — the **core enforcement library** that
owns Cedar authorization, audit logging, PII detection/masking, field-level
encryption, and data access. The core is the gate.

## Key architecture decisions (already made)

- **100% open source.** Calling card for the consulting practice; full auditability.
- **Pragmatic minimalism on dependencies.** Aggressively avoid incidental/transitive
  deps. Keep load-bearing specialist libraries — Cobra, a Cedar engine, an OAuth
  library, an MCP SDK, the Postgres driver — because re-implementing authz, crypto,
  or protocol code is itself a security risk. Anything else: prefer stdlib, vendor
  what is used, justify every addition.
- **Per-client deployment repos** are thin (schema manifest + per-client config +
  instantiated IaC + a pinned Kura version), scaffolded by `kura init`, named per
  client, handed off to the client. The scaffold template lives inside the `kura`
  repo.
- **The schema manifest is the keystone** — one per-client file (entities,
  relationships, PII-sensitivity tags) drives the data browser, the CLI `query`
  verbs, the MCP data tools, and the Cedar policy matrix.
- **Declarative IaC** (Terraform), DigitalOcean Standard-Regulated happy path shipped
  as a tested baseline. Heavily-Regulated (AWS/GCP) stays agent-generated per spec.
- **Testing is tiered:** per-commit (unit + containerized Postgres + static IaC
  policy + `terraform plan` snapshots), per-release (ephemeral real-DO end-to-end),
  optional long-lived staging. `kura smoke` is the single artifact shared by CI and
  the provisioning agent's Definition of Done.

## Companion documents

This plan says **what** to build. Two companion docs in this directory carry the rest
— and an agent landing on any one of the three should know the other two exist:

- **`2026-05-14-architecture.md`** — the **why**: the reasoning behind the system's
  shape, the alternatives rejected, and the deliberate deviations from the reference
  architecture. Read it before changing a structural decision; the plan deliberately
  does not duplicate this rationale.
- **`2026-05-14-cli-design-guidelines.md`** — **how the CLI behaves**: the
  agent-native CLI principles every `kura` command must follow.

The spec this plan implements is the `nobedan` repo's `template/data-storage/` docs —
`02-for-nobedan.md` (the strategic playbook) and `03-for-agents.md` (the reference
architecture).

## How to use this plan

```sh
job import 2026-05-14-kura-build-plan.md --dry-run   # preview the tree
job import 2026-05-14-kura-build-plan.md             # commit it
job status                                          # session opener
job claim --next                                    # grab the next available leaf
```

Phases are gated with `blockedBy`. Strict red/green TDD applies throughout: every
implementation leaf is expected to land failing tests first. Phase 0's five
architectural decisions were resolved with the user before import; they remain as
tasks only to record each rationale in `docs/` and apply the decision in code.

---

```yaml
tasks:
  - title: "Phase 0 — Repo foundation & key decisions"
    ref: phase-0
    labels: [phase-0, foundation]
    desc: |
      Stand up the `kura` repo skeleton and resolve the architectural decisions that
      everything downstream depends on. Nothing here ships product behavior; it makes
      the rest of the plan buildable and unblocks the open questions.

      The repo already exists at ~/git/kura (currently empty apart from project/).
    children:
      - title: "Initialize Go module and project layout"
        ref: repo-layout
        labels: [foundation]
        desc: |
          Create the Go module and the directory skeleton, modeled on `job`
          (~/git/jobs): `cmd/kura/` for the Cobra command tree (one file per verb),
          `internal/` for the core enforcement library and all domain logic,
          `internal/migrations/` for forward-only SQL migrations. Add a Makefile with
          build/test/install/fmt targets. Pick the module path and the Go version
          (match or exceed `job`'s).

          Pragmatic minimalism starts here: the only dependencies added in this task
          are Cobra and the Postgres driver. Every later dependency needs a
          justification in its own task.
        criteria:
          - "go.mod exists with module path and Go version pinned"
          - "directory skeleton matches the cmd/ + internal/ + internal/migrations/ shape"
          - "Makefile has build, test, fmt, install targets and they run"
          - "`kura --help` runs and prints a (stub) command tree"
      - title: "Write the docs/ skeleton"
        labels: [foundation, docs]
        desc: |
          Assess the repo's agent-facing development guide (AGENTS.md, symlinked from
          CLAUDE.md as `job` does): strict red/green TDD discipline, the
          adapter-over-core rule, dependency-minimalism policy, git hygiene. Stand up
          a docs/ tree (agent-first, like `job`'s) with placeholder sections for
          machine-interface, concepts, getting-started, and recipes. Link
          project/2026-05-14-cli-design-guidelines.md as the canonical CLI reference.
        criteria:
          - "AGENTS.md states the TDD, adapter-over-core, and dependency rules"
          - "CLAUDE.md is a symlink to AGENTS.md"
          - "docs/ skeleton exists with section placeholders"
      - title: "Set up the per-commit CI skeleton"
        ref: ci-skeleton
        labels: [foundation, testing]
        desc: |
          A CI pipeline that runs on every commit: `go build`, `go vet`, `go fmt`
          check, `go test ./...`. It will grow (containerized Postgres, static IaC
          policy checks, `terraform plan` snapshots) as later phases land — wire
          those in as their phases complete. Keep it fast; the expensive real-DO e2e
          is a separate per-release pipeline (Phase 8).
        criteria:
          - "CI runs build + vet + fmt-check + test on every commit"
          - "CI is green on the Phase 0 skeleton"
      - title: "Record & apply: consultant authentication model"
        ref: dec-consultant-auth
        labels: [foundation, docs]
        desc: |
          RESOLVED before import. The consultant is a distinct Cedar principal type
          (`Consultant`), NOT a guest in the client's Google Workspace. Authentication
          is still Google OAuth, but against the consulting firm's own Workspace
          domain (`nobedan.com`): the client's deployment config trusts that domain
          for the `Consultant` principal type only, separately from the client domain
          that maps to `User`/`Admin`. The consultant's agent acts AS the consultant —
          `kura login` signs in `ben@nobedan.com` and the agent uses that short-lived
          token; there is no separate per-agent principal in v1 (the human owns the
          session, and the audit log attributes to them). Re-engagement = re-add the
          firm-domain trust.

          Why: the consulting firm controls consultant offboarding (not the client),
          consultant actions are distinct in the audit log, and engagement-end is a
          config change. Shapes `kura login`, the token model, and the Cedar principal
          schema (the Phase 1 identity task, Phase 2 server-auth task).
        criteria:
          - "the decision and rationale are written into docs/concepts/"
          - "the Cedar principal schema models User/Admin, Consultant, and service/agent types"
          - "the decision is added to the architecture doc's 'Decisions already closed' section"
      - title: "Record & apply: DigitalOcean secrets-backend default"
        ref: dec-secrets-backend
        labels: [foundation, docs]
        desc: |
          RESOLVED before import. The Standard-Regulated DO secrets backend is
          **Doppler**. Self-hosted Vault rejected — too much ongoing ops for the
          SMB-tech-owner handoff target (it would rot post-handoff). Cross-cloud AWS
          Secrets Manager rejected — forces a second cloud account on a DO client and
          a worse bootstrap story. Doppler is low-ops, SOC 2-attested, does runtime
          injection, and holds only secrets (not PII), so the added-sub-processor
          surface is bounded. The Doppler account is client-owned (infra lives in the
          client's account, never the firm's), provisioned during the engagement, and
          handed off with the rest of the stack.

          Blocks the secrets-manager abstraction (Phase 1 secrets task) and the IaC
          baseline (Phase 6).
        criteria:
          - "the choice and rationale are recorded in docs/ and the architecture doc"
          - "the Phase 1 secrets task and Phase 6 secrets-provisioning task reference Doppler"
      - title: "Record & apply: Cedar policy-apply ceremony (v1)"
        ref: dec-policy-apply
        labels: [foundation, docs]
        desc: |
          RESOLVED before import. v1 posture: the server loads its Cedar policy from
          the deployment repo at startup/deploy time. Changing policy = change the
          repo, redeploy. There is NO `kura policy apply` command in v1 and no
          watch-and-reload — v1's Cedar UI is read-only, nothing changes policy on a
          running surface, so a live apply path solves a problem that does not yet
          exist. PR-gating comes for free (changing the repo is a PR). The dedicated
          apply ceremony is revisited when the structured Cedar *editor* lands (a
          future phase), decided then with real requirements.
        criteria:
          - "the v1 deploy-time-load posture is documented in docs/concepts/ and the architecture doc"
      - title: "Record & apply: agent-context generation mechanism"
        ref: dec-ops-registry
        labels: [foundation, docs]
        desc: |
          RESOLVED before import. CLI commands, MCP tools, and `kura agent-context`
          all project from a Go-native operations registry in `internal/` — a registry
          of `Operation` values (name, summary, typed args with validation, handler).
          NOT reflection from Go types, NOT a separate schema file. The source of
          truth stays in Go code (no separate file to drift, per `job`'s lesson) but
          it is explicit data rather than reflection magic. The plan's drift test
          becomes trivial: all three surfaces read the same slice. Shapes how every
          command, MCP tool, and introspection entry is authored from the Phase 3 CLI
          skeleton onward.
        criteria:
          - "the operations-registry mechanism is documented in docs/"
          - "a minimal proof-of-concept generates one command + its agent-context entry from the registry"
      - title: "Record & apply: Terraform for IaC"
        ref: dec-terraform
        labels: [foundation, docs]
        desc: |
          RESOLVED before import. The DO Standard-Regulated baseline uses
          **Terraform**, not Pulumi. Deciding factor: the IaC ships in the thin
          per-client repo handed to an SMB tech owner, and declarative HCL is far more
          readable to a non-Go person than Pulumi Go code — "configuration is code"
          only helps if they can read it. Plan/apply also maps to doc 02's "read the
          agent's plan before it runs," and the plan's IaC test strategy
          (tflint/Conftest, `terraform plan` snapshots) is already Terraform-shaped.
          Terraform is a separate tool, not a Go-module dependency, so it does not
          touch Kura's supply-chain surface.
        criteria:
          - "the Terraform decision and rationale are recorded in docs/ and the architecture doc"

  - title: "Phase 1 — Core enforcement library"
    ref: phase-1
    labels: [phase-1, core]
    blockedBy: [phase-0]
    desc: |
      Build `internal/` — the single source of truth. Cedar authorization, audit
      logging, PII detection/masking, field-level encryption, data access, and the
      schema-manifest model all live here. The API, CLI, dashboard, and MCP are later
      adapters over this; nothing in those layers may hold a policy decision, an audit
      write, or a masking rule.

      This is the highest-risk code in Kura. Strict red/green TDD. Integration tests
      run against a containerized Postgres — never DO's Postgres; DO Managed Postgres
      is just hosted Postgres.
    children:
      - title: "Schema manifest: model, parser, and validation"
        ref: manifest
        labels: [core, tdd]
        desc: |
          The keystone. A per-client manifest declares entities, relationships, and
          which fields carry which PII-sensitivity categories. This one file later
          drives the data browser, the CLI `query`/`show` verbs, the MCP data tools,
          and the Cedar policy matrix.

          Build the in-memory model, a parser for the manifest file format, and strict
          validation (unknown entity references, dangling relationships, unrecognized
          sensitivity categories all fail loudly). Decide the file format (YAML is the
          obvious default) and write the format reference into docs/.
        criteria:
          - "a valid manifest parses into the model; relationships resolve"
          - "every malformed-manifest case fails validation with a specific error"
          - "the manifest format is documented in docs/"
      - title: "Identity & principal model"
        ref: identity
        labels: [core, tdd]
        desc: |
          Define the principal types Cedar will reason about (human user, consultant,
          service/agent — per the Phase 0 consultant-auth decision) and the
          token-backed identity model. Unlike `job`, identity here has teeth: a
          principal is a security boundary, and every action is attributed to one in
          the audit log. No anonymous path, no "trusted CLI" path. Short-lived tokens;
          the token IS the identity.
        criteria:
          - "principal types are modeled and map to Cedar entity types"
          - "token issuance/validation works with short-lived expiry"
          - "an unauthenticated request resolves to no principal and is denied"
      - title: "Audit logging subsystem"
        ref: audit
        labels: [core, tdd]
        desc: |
          Append-only audit log capturing actor, resource, action, and time for every
          access and authorization decision. The data contents are NEVER in the log.
          Authentication and authorization events are logged distinctly. The audit log
          is itself sensitive but at a different category than the data — it targets
          its own store with its own retention (see object storage, Phase 1 + 6).
          Provide the query and stream primitives the CLI `log`/`tail` and the
          dashboard's audit viewer will consume.
        criteria:
          - "every access and authz decision emits a structured audit event"
          - "no test can produce data contents in an audit record"
          - "audit events are queryable by actor, resource, action, and time range"
      - title: "Cedar policy IR, IR-to-Cedar compiler, and evaluation wrapper"
        ref: cedar
        labels: [core, tdd]
        desc: |
          Authorization. Three pieces:
          (1) a structured intermediate representation (IR) of the policy space —
              roles x entities x PII-categories x actions — whose axes come from the
              schema manifest;
          (2) a compiler from the IR to Cedar policy text;
          (3) an evaluation wrapper around the chosen Cedar engine that decides each
              request against principal, action, resource, and the resource's detected
              PII categories (not just column names).

          The IR is deliberately the same model the dashboard's structured viewer
          (Phase 4) renders and the future structured editor will edit — build it once
          here. Free-form Cedar authoring stays a repo/PR activity; the IR expresses
          only the constrained, safe subset.

          Dependency note: select a Cedar engine for Go and record the choice and its
          maturity in docs/. If no suitable engine exists, escalate — re-implementing
          Cedar evaluation is out of scope and a security risk.
        criteria:
          - "the IR models roles x entities x PII-categories x actions from a manifest"
          - "IR compiles to valid Cedar policy text"
          - "the evaluator decides requests against detected PII categories, not column names"
          - "the default three-role model (admin, user, read-only auditor) is expressible in the IR"
      - title: "PII detection integration"
        ref: pii
        labels: [core, tdd]
        desc: |
          Wire in the PII detection layer (doc 03 default: OpenAI Privacy Filter,
          Apache-2.0, self-hosted — verify it and record deployment details in docs/).
          It runs as a separate internal-only service; the core calls it over a
          narrow client interface.

          Two call sites: at INGESTION (every free-text field scanned; detected spans
          stored as structured metadata — category, offset, length, confidence) and at
          ACCESS time (re-scan when policy requires category-based masking, catching
          drift if the model improves between ingestion and access). Build the client
          interface with a fake for unit tests so the core's tests don't require the
          live service.
        criteria:
          - "the PII client interface has a test fake and a real implementation"
          - "ingestion produces category/offset/length/confidence metadata for free-text fields"
          - "access-time detection is invokable for category-based masking"
      - title: "Database layer: schema, migrations, extensions, users, RLS, encryption"
        ref: db
        labels: [core, tdd]
        desc: |
          The Postgres layer. Forward-only migrations in internal/migrations/.
          Required extensions: pgaudit (forensic query logging) and pgcrypto
          (field-level encryption primitives) — verify both are available on the
          targeted DO Managed Postgres major version and record the finding.

          Per-component DB users with minimum privilege: an API user scoped to the
          application schema, a provisioning/admin user, a read-only audit user. TLS
          required; non-TLS refused. Row-level security enabled on multi-tenant tables
          even while single-tenant. Field-level encryption for high-sensitivity
          categories (SSNs, financial/government IDs, medical record numbers,
          biometrics); free-text columns encrypted at the column level by default.

          Structured records and metadata go in Postgres; large blobs go to object
          storage (see storage task). Integration-tested against a containerized
          Postgres.
        criteria:
          - "migrations apply cleanly from empty to current on a containerized Postgres"
          - "pgaudit and pgcrypto load on the targeted version (or the blocker is surfaced)"
          - "per-component users exist with documented minimum privileges"
          - "RLS is enabled on multi-tenant tables; a cross-tenant read is denied in a test"
          - "high-sensitivity fields are field-level encrypted; free-text columns encrypted at rest"
      - title: "Object storage abstraction"
        ref: storage
        labels: [core, tdd]
        desc: |
          Two distinct buckets, distinct credentials, distinct retention: a BACKUPS
          bucket (encrypted, separate region, 30-35 day retention, written only by
          primary infra) and an AUDIT-LOG bucket (encrypted, append-only, 1-2 year
          retention, written only by the API). Build a storage interface with a local
          fake for tests; the real DO Spaces implementation is exercised by the IaC
          phase. Buckets are private always; lifecycle/retention is enforced by
          policy, never by manual deletion.

          Immutability note: DO Spaces has no Object Lock / WORM. The achievable
          posture — and what the model targets — is versioning enabled plus a
          deny-delete bucket policy (denying object/version deletion and
          versioning-disable), administered from a credential domain separate from the
          runtime writer. The runtime writer can append but effectively cannot
          destroy. True WORM is the Heavily-Regulated (AWS/GCP) tier; this is the
          proportionate Standard-Regulated posture given Kura's threat model. The
          storage interface models this — an append-only role is distinct from a
          read-write role — so the fake and the real implementation agree on it.
        criteria:
          - "the storage interface has a test fake and supports both bucket roles"
          - "backups and audit-log buckets have distinct credential domains in the model"
          - "retention is expressed as policy, not manual action"
          - "the append-only role rejects delete/overwrite in the fake, matching the deny-delete posture"
      - title: "Secrets manager abstraction"
        ref: secrets
        labels: [core, tdd]
        desc: |
          All secrets — DB passwords, OAuth client secrets, encryption keys, API keys
          — come from a secrets manager, injected at runtime, never baked into images
          or committed. Build an interface over the backend chosen in Phase 0; provide
          a test fake. Access to secrets is itself authenticated and audited. Encryption
          keys are managed and rotatable, not hardcoded.
        criteria:
          - "the secrets interface has a test fake and the chosen-backend implementation"
          - "no secret is ever read from a baked-in env var or committed file in any code path"
          - "secret access emits an audit event"
      - title: "LLM access gateway"
        ref: llm-gw
        labels: [core, tdd]
        desc: |
          A thin gateway for calls to LLM providers (Anthropic by default). Logs
          metadata only — timestamp, principal, model, token count, prompt hash,
          response hash — NEVER prompt or response contents. Validates at startup that
          the controller's DPA is on file for the provider before any calls are
          allowed. Default data flow: the client owns the Anthropic account and the
          API uses their key.
        criteria:
          - "every LLM call emits a metadata-only audit event (hashes, not contents)"
          - "startup fails closed if the DPA configuration check does not pass"
      - title: "Core enforcement assembly — the gate"
        ref: gate
        labels: [core, tdd]
        blockedBy: [manifest, identity, audit, cedar, pii, db]
        desc: |
          Tie the pieces into the single enforcement entrypoint every adapter calls:
          authenticate the principal -> evaluate Cedar against the request and the
          resource's detected PII categories -> perform the data access -> apply
          category-based masking -> emit the audit event. This is "the core is the
          gate" made concrete. The API, CLI (`--local`), dashboard, and MCP all go
          through here; none may reconstruct any of these steps themselves.
        criteria:
          - "a single core entrypoint performs authn -> authz -> access -> mask -> audit"
          - "a request that skips any step is impossible by construction (not by convention)"
          - "masking output is identical regardless of the caller (API/CLI/MCP)"

  - title: "Phase 2 — HTTP API server (kura serve)"
    ref: phase-2
    labels: [phase-2, server]
    blockedBy: [phase-1]
    desc: |
      The remote server and the only public surface. A JSON API over the core gate,
      plus the OAuth callback. No HTML, no dashboard pages — the dashboard is a
      separate local adapter (Phase 4). This keeps the public attack surface to
      "just the JSON API," honoring doc 03's network-minimum-exposure principle with
      no asterisk. Assume Caddy terminates TLS in front (configured in Phase 6); the
      server still requires TLS-aware handling and trusts the forwarded real client
      IP for audit logging.
    children:
      - title: "HTTP server skeleton and `kura serve` command"
        ref: server-skeleton
        labels: [server, tdd]
        desc: |
          The `kura serve` subcommand and the HTTP server: routing (prefer stdlib
          net/http; justify any router dependency), graceful shutdown, structured
          request logging to stderr, health endpoints. Every route authenticated
          before business logic. Paths over queries (`/api/people/89`, not
          `?id=89`); queries reserved for search/sort/filter.
        criteria:
          - "`kura serve` starts, binds, serves health, and shuts down gracefully"
          - "an unauthenticated request to any data route is rejected before business logic"
      - title: "Token auth and `kura login` OAuth flow"
        ref: server-auth
        labels: [server, tdd]
        blockedBy: [server-skeleton]
        desc: |
          Implement the server side of authentication per the Phase 0 consultant-auth
          decision: the OAuth flow (loopback-callback vs device flow — decide and
          document), short-lived token issuance, and token validation middleware that
          resolves every request to a Cedar principal. Human users for the dashboard
          and agent/CLI users both authenticate here; there are no API keys for human
          users.
        criteria:
          - "the OAuth flow completes end-to-end against a real Google Workspace test domain"
          - "a valid token resolves to the correct Cedar principal; an expired one is rejected"
          - "auth events are audited distinctly from authorization events"
      - title: "Audit middleware and boundary authorization"
        labels: [server, tdd]
        blockedBy: [server-skeleton]
        desc: |
          Middleware that ensures every request flows through the core gate: principal
          resolved, Cedar consulted, audit event emitted, real client IP recorded. The
          server must not be able to serve a data response that bypassed the gate.
        criteria:
          - "every data response in tests carries a corresponding audit event"
          - "a route that bypasses the gate fails an architectural test"
      - title: "Data endpoints (manifest-driven, masked)"
        ref: server-data
        labels: [server, tdd]
        blockedBy: [server-auth]
        desc: |
          CRUD and query endpoints generated from the schema manifest: list/get
          entities with filtering, sorting, pagination, and related entities returned
          as trees. All reads pass through access-time PII masking. Bounded by default
          (sane page sizes) — these feed the CLI `query`/`show` and the dashboard data
          browser, both of which must never dump unbounded result sets.
        criteria:
          - "endpoints exist for every entity in a test manifest"
          - "responses are masked per the requesting principal's policy"
          - "list endpoints are paginated with a documented default limit"
      - title: "User, role, and policy endpoints"
        labels: [server, tdd]
        blockedBy: [server-auth]
        desc: |
          Endpoints for the authorized-user list, role assignment, and read access to
          effective Cedar policy (rendered from the IR). Policy *authoring* is not a
          server endpoint — it stays a repo/PR activity per the Phase 0 decision.
          Deactivation is largely an identity-provider concern (Workspace suspension);
          these endpoints surface and manage the authorized list and role
          assignments, and flag IdP mismatches (suspended account still holding a role).
        criteria:
          - "users can be added to the authorized list and assigned/revoked roles (variadic, atomic)"
          - "effective policy is readable; policy authoring has no write endpoint"
          - "an IdP mismatch (suspended Google account, role still assigned) is detectable"
      - title: "Audit-log query and stream endpoints"
        labels: [server, tdd]
        blockedBy: [server-auth]
        desc: |
          Read endpoints over the audit subsystem: filter by actor/resource/action/
          time, plus a streaming endpoint (JSON-lines) for live observation — the
          basis for the CLI `tail` and the dashboard's audit viewer. Access to the
          audit log is itself authorized and audited.
        criteria:
          - "audit queries support actor/resource/action/time filters"
          - "the stream endpoint emits JSON-lines and is itself access-controlled"
      - title: "LLM gateway endpoint"
        labels: [server, tdd]
        blockedBy: [server-auth]
        desc: |
          Expose the core LLM gateway over HTTP: callers go through it rather than
          calling Anthropic directly, so every call is metadata-logged and the DPA
          check is enforced. For the Standard-Regulated tier this is Anthropic direct
          with the controller's key.
        criteria:
          - "LLM calls via the endpoint are metadata-logged (hashes, not contents)"
          - "the endpoint refuses to serve if the startup DPA check failed"
      - title: "Smoke-suite foundation"
        ref: server-smoke
        labels: [server, tdd]
        blockedBy: [server-data]
        desc: |
          The server-side hooks the `kura smoke` suite (completed in Phase 8) needs:
          end-to-end checks for the auth flow, the audit-log flow, the PII detection
          flow, and the LLM gateway metadata flow. Designed so the same suite runs
          against a CI ephemeral deploy, a staging environment, and a freshly
          provisioned client system.
        criteria:
          - "smoke checks exist for auth, audit, PII, and LLM-gateway flows"
          - "the suite is invokable against an arbitrary running server by URL"

  - title: "Phase 3 — CLI (kura <verb>)"
    ref: phase-3
    labels: [phase-3, cli]
    blockedBy: [phase-2]
    desc: |
      The CLI: by default a local agent's HTTP client to a remote `kura serve`.
      `--local` (direct core access) is the break-glass exception. Build strictly to
      project/cli-design-guidelines.md — non-interactive, Markdown-default output
      with `--json` opt-in and identical masking across both, identity with teeth,
      greppable error contracts pinned by tests, a documented exit-code taxonomy,
      set- and tree-shaped operations, acks that teach, profiles with no credentials.
    children:
      - title: "CLI skeleton: command tree, global flags, HTTP client and --local mode"
        ref: cli-skeleton
        labels: [cli, tdd]
        desc: |
          The Cobra command tree (one file per verb, like `job`), global flags
          (`--server`, `--client` profile selector, `--as`, `--json`, `--local`,
          `--confirm`), the HTTP client that targets a remote server, and the
          `--local` path that calls the core gate directly for break-glass. Per the
          Phase 0 decision, the command surface is authored via the chosen
          operations-definition mechanism so CLI/MCP/agent-context cannot drift.
        criteria:
          - "the command tree builds; global flags parse"
          - "a verb runs in both HTTP-client mode and --local mode against the same core behavior"
          - "shell/env state is never required between invocations; flags and profiles carry state"
      - title: "Output and error layer"
        ref: cli-output
        labels: [cli, tdd]
        blockedBy: [cli-skeleton]
        desc: |
          The shared rendering layer: dense Markdown by default, `--json` opt-in with
          stable schemas, stdout-data / stderr-diagnostics separation, ANSI suppressed
          off-TTY. Masking is applied in the core and rendered identically into both
          formats — pin this with a test. Greppable, enumerating error messages with
          stable first-line prefixes, pinned by tests (the `job`
          `...ErrorPrefixIsGreppable` pattern). The documented exit-code taxonomy
          (success / validation / auth / not-found / conflict / transient) implemented
          and pinned.
        criteria:
          - "Markdown and --json outputs carry identical masking for the same principal"
          - "error prefixes are stable and asserted by tests"
          - "the exit-code taxonomy is implemented, documented, and test-pinned"
      - title: "Session commands: login, logout, status"
        labels: [cli, tdd]
        blockedBy: [cli-output]
        desc: |
          `kura login` (the OAuth flow from Phase 2, caching a short-lived token),
          `kura logout`, and `kura status` — the session opener, modeled on `job
          status`: which server and profile, the resolved identity, the deployment
          tier, what is provisioned vs pending, and any audit anomalies needing
          attention. An agent runs `kura status` first, every session.
        criteria:
          - "`kura login` completes the OAuth flow and caches a short-lived token"
          - "`kura status` orients an agent cold: server, identity, tier, anomalies"
      - title: "Profiles (--client multi-target, no credentials)"
        labels: [cli, tdd]
        blockedBy: [cli-skeleton]
        desc: |
          A consultant's laptop addresses N client servers. `kura --client <name>`
          resolves to an endpoint plus non-secret config. Profiles store endpoints and
          output preferences and NEVER credentials — tokens stay short-lived from
          `kura login`. Provide `kura profile` management verbs.
        criteria:
          - "`--client <name>` resolves to the right endpoint and config"
          - "no credential is ever written to a profile (asserted by a test)"
      - title: "User and role commands"
        labels: [cli, tdd]
        blockedBy: [cli-output]
        desc: |
          `kura user list/add/show/deactivate` and `kura role assign/revoke/list`.
          Variadic and atomic mutations. Acks that teach — after `user add`, hint the
          role-assignment command. `role list` shows effective policy read-only.
        criteria:
          - "user and role mutations are variadic, atomic, and idempotent"
          - "success acks include a next-step hint"
      - title: "Data commands: query and show (manifest-driven)"
        labels: [cli, tdd]
        blockedBy: [cli-output]
        desc: |
          `kura query <entity>` (filtered, bounded, paginated, masked to the caller's
          access level) and `kura show <entity> <id>` (single record with related
          entities as a tree). Generic across whatever the schema manifest defines —
          this is the CLI face of the sanity-check data browser.
        criteria:
          - "query and show work for every entity in a test manifest"
          - "results are masked to the caller's principal and bounded by default"
      - title: "Audit commands: log and tail"
        labels: [cli, tdd]
        blockedBy: [cli-output]
        desc: |
          `kura log` (filterable audit query) and `kura tail` (JSON-lines streaming of
          audit events — e.g. watch auth failures live), consuming the Phase 2 audit
          endpoints.
        criteria:
          - "`kura log` filters by actor/resource/action/time"
          - "`kura tail` streams JSON-lines and terminates cleanly"
      - title: "Async: --wait and the jobs ledger"
        labels: [cli, tdd]
        blockedBy: [cli-output]
        desc: |
          `--wait` on long-running operations with internal polling/backoff, and a
          durable `kura jobs list/get` ledger that survives disconnects so retries
          find existing work instead of duplicating it. Relevant to provisioning
          steps, backup verification, and restore tests.
        criteria:
          - "`--wait` polls internally and returns on completion or timeout"
          - "the jobs ledger survives a process restart; a retry finds existing work"
      - title: "Backup and restore commands"
        ref: cli-backup
        labels: [cli, tdd]
        blockedBy: [cli-output]
        desc: |
          `kura backup` and `kura restore` — the independent logical-backup tier that
          earns the security improvement over bare DO Managed Postgres. DO's built-in
          managed backups stay on (free, default, ~7-day PITR) for fast operational
          recovery, but they share the primary's credential domain. `kura backup`
          adds the compromise-resilient copy: it dumps the DB, encrypts with a key
          from the secrets manager that is DISTINCT from the runtime field-encryption
          keys, and writes to the separate-region BACKUPS bucket via the append-only
          storage role.

          The orchestration logic lives in `internal/` per the adapter-over-core
          rule; the `cmd/` files are wiring. Run on-box via `--local` (it touches the
          DB directly and is invoked by the Phase 6 scheduled job), audited like any
          other action, and tracked in the jobs ledger so `--wait` and retry-finds-
          existing-work both apply. `kura restore` performs a restore to a target and
          is the command `smoke-complete`'s backup-restore check invokes.
        criteria:
          - "`kura backup` produces an encrypted dump in the backups bucket via the append-only role"
          - "the backup encryption key is sourced from secrets and is distinct from runtime keys"
          - "`kura restore` restores to a throwaway target and the result is verifiable"
          - "both commands are audited and appear in the jobs ledger"
      - title: "agent-context introspection output"
        labels: [cli, tdd, docs]
        blockedBy: [cli-skeleton]
        desc: |
          `kura agent-context`: a versioned, machine-readable JSON description of the
          entire command tree, generated via the Phase 0 operations-definition
          mechanism so it cannot drift from the real commands. The middle layer of the
          three-layer introspection model (`--help` / `agent-context` / recipes).
        criteria:
          - "`kura agent-context` emits versioned JSON covering every command and flag"
          - "it is generated, not hand-maintained; a drift test fails if a command is missing"
      - title: "kura smoke command"
        labels: [cli, tdd]
        blockedBy: [cli-output]
        desc: |
          `kura smoke --server <url>`: runs the smoke suite (foundation from Phase 2,
          completed in Phase 8) against a target server. One artifact, three uses —
          CI's ephemeral deploy, the staging environment, and the provisioning agent's
          per-engagement Definition of Done.
        criteria:
          - "`kura smoke --server <url>` runs the suite and reports pass/fail per check"
          - "exit code follows the taxonomy (clean pass vs failures vs unreachable)"

  - title: "Phase 4 — Local dashboard (kura dashboard)"
    ref: phase-4
    labels: [phase-4, dashboard]
    blockedBy: [phase-2]
    desc: |
      A human-facing web app that runs LOCALLY (`kura dashboard`), bound to loopback,
      and is itself an HTTP client of the remote API — exactly like the CLI. Running
      it locally keeps the webapp's whole vuln surface (XSS, CSRF, sessions,
      templates) off the public internet; the remote server stays API-only. Audience
      is small (1-3 admins per client) and they already have the `kura` binary, so
      local distribution is acceptable. No mobile target — custom apps cover that
      later. Vanilla HTML/CSS/JS, no inline styles, responsive; auth via the
      `kura login` token.
    children:
      - title: "Dashboard skeleton: local server, loopback bind, API client, auth"
        ref: dash-skeleton
        labels: [dashboard, tdd]
        desc: |
          The `kura dashboard` subcommand: a local web server bound to 127.0.0.1
          (the `job serve` pattern), serving the app shell, authenticating to the
          remote API with the cached `kura login` token, and proxying/calling the API
          for all data. No direct database access; no server-side PII rendering on a
          shared host.
        criteria:
          - "`kura dashboard` serves on loopback and authenticates to the remote API"
          - "all data access goes through the remote API, never the database directly"
      - title: "Overview page"
        labels: [dashboard, tdd]
        blockedBy: [dash-skeleton]
        desc: |
          System status, deployment tier, record/user counts, recent activity, and a
          "needs attention" panel: IdP mismatches (suspended Google account still
          holding a role), an overdue quarterly access review, audit anomalies.
        criteria:
          - "the overview shows status, tier, counts, and a populated needs-attention panel"
      - title: "Users & roles page"
        labels: [dashboard, tdd]
        blockedBy: [dash-skeleton]
        desc: |
          Manage the authorized-user list, assign/revoke roles, view effective policy
          per user, flag IdP mismatches. Role *assignment* is data and lives here;
          policy *authoring* does not (repo/PR).
        criteria:
          - "users can be managed and roles assigned/revoked from the UI"
          - "effective policy per user is visible; there is no free-form policy editor"
      - title: "Access review workflow"
        labels: [dashboard, tdd]
        blockedBy: [dash-skeleton]
        desc: |
          The quarterly access review, run entirely in the local dashboard (locked
          decision — no emailed remote link). Presents the access list, approve/remove
          per person, and archives the completed review as an artifact.
        criteria:
          - "a reviewer can approve/remove each person and complete a review"
          - "a completed review is archived as a retrievable artifact"
      - title: "Data browser (manifest-driven, masked)"
        labels: [dashboard, tdd]
        blockedBy: [dash-skeleton]
        desc: |
          A generic, schema-manifest-driven browser — browse entities, follow
          relationships, view records, all masked to the viewer's access level. Not a
          CRM; a sanity-check tool. It hits the API directly so it stays a valid check
          when the client's own application is the thing malfunctioning.
        criteria:
          - "the browser renders any entity/relationship from a test manifest with no entity-specific code"
          - "records are masked to the viewer's principal"
      - title: "Audit log viewer"
        labels: [dashboard, tdd]
        blockedBy: [dash-skeleton]
        desc: |
          A searchable, filterable view over the audit endpoints — actor, resource,
          action, time. The human counterpart to `kura log`.
        criteria:
          - "the viewer filters by actor/resource/action/time and paginates"
      - title: "Cedar structured viewer"
        labels: [dashboard, tdd]
        blockedBy: [dash-skeleton]
        desc: |
          V1 of the Cedar UI: a read-only STRUCTURED VIEWER rendering the policy IR
          (from Phase 1) — roles x entities x PII-categories x actions as a readable
          grid plus plain-language statements. Deliberately a baby-step toward a
          future structured *editor*: it reads the exact IR the editor will later
          edit, and ships the IR-to-Cedar compile path, so nothing is throwaway.
          Free-form Cedar authoring stays repo/PR.
        criteria:
          - "effective policies render as a structured, human-readable grid from the IR"
          - "the viewer reads the same IR model the future editor will edit"
      - title: "Programmatic-access docs page"
        labels: [dashboard, tdd, docs]
        blockedBy: [dash-skeleton]
        desc: |
          An in-dashboard page explaining how to use the API, CLI, and MCP
          programmatically, including the user's own token-issuance flow.
        criteria:
          - "the page documents API, CLI, and MCP access and the token-issuance flow"

  - title: "Phase 5 — MCP server (kura mcp)"
    ref: phase-5
    labels: [phase-5, mcp]
    blockedBy: [phase-2]
    desc: |
      The MCP adapter — the typed agent surface, primarily for a client's own agents
      post-handoff. Local proxy by default (`kura mcp --server <url>`, stdio
      transport); remote-served over HTTP is an option for client-side agents.
      Generated from the same operations definition as the CLI so the two cannot
      drift. MCP carries none of the webapp's XSS/CSRF surface — it is structurally
      close to the API.
    children:
      - title: "MCP server skeleton (local proxy + remote-served modes)"
        ref: mcp-skeleton
        labels: [mcp, tdd]
        desc: |
          The `kura mcp` subcommand using the chosen Go MCP SDK (verify and record the
          choice). Local stdio-transport proxy mode targeting a remote `--server`, and
          a remote-served HTTP mode. Tools are projected from the Phase 0
          operations-definition mechanism.
        criteria:
          - "`kura mcp` runs as a local stdio proxy to a remote server"
          - "a remote-served HTTP mode is available"
          - "tools are generated from the operations definition, not hand-written"
      - title: "Manifest-driven data tools"
        labels: [mcp, tdd]
        blockedBy: [mcp-skeleton]
        desc: |
          MCP tools for querying and showing entities, generated from the schema
          manifest — the MCP face of the data browser. All results masked through the
          core gate; tool descriptions kept tight to minimize token cost.
        criteria:
          - "data tools exist for every entity in a test manifest"
          - "tool results are masked identically to the CLI and API for the same principal"
      - title: "Admin tools (user/role/audit parity)"
        labels: [mcp, tdd]
        blockedBy: [mcp-skeleton]
        desc: |
          MCP tools for user/role management and audit queries, at parity with the
          corresponding CLI commands. A behavioral-parity test asserts CLI and MCP
          stay in sync.
        criteria:
          - "user/role/audit tools match the CLI's capabilities"
          - "a parity test fails if a CLI capability has no MCP equivalent (or vice versa)"

  - title: "Phase 6 — Deployment baseline (DigitalOcean Standard-Regulated IaC)"
    ref: phase-6
    labels: [phase-6, iac]
    blockedBy: [phase-1]
    desc: |
      The tested, known-good IaC baseline for the DO Standard-Regulated happy path —
      the refinement of doc 03's "agent generates artifacts" stance: for the path run
      repeatedly, maintain a baseline rather than regenerating each time.
      Heavily-Regulated (AWS/GCP) stays agent-generated per the reference architecture.
      IaC tool per the Phase 0 confirmation (working assumption: Terraform).
    children:
      - title: "Core DO infrastructure"
        ref: iac-core
        labels: [iac]
        desc: |
          The DO resources: VPC and Cloud Firewall (database never publicly
          reachable), Managed Postgres (with pgaudit/pgcrypto), Droplets for the API
          and the PII detection service, Spaces for the backups and audit-log buckets,
          Tailscale for admin/SSH access (no public SSH). Provisioning order from doc
          03 encoded as dependencies. Parameterized by the per-client config so one
          baseline serves every Standard-Regulated engagement.
        criteria:
          - "`terraform apply` (or equivalent) stands up the full resource set in a test DO account"
          - "the database has no public port; SSH is Tailscale-only"
          - "the two buckets are private with distinct credentials and lifecycle/retention rules"
          - "both buckets have versioning enabled and a deny-delete bucket policy administered from a separate credential domain"
      - title: "Caddy reverse proxy configuration"
        labels: [iac]
        blockedBy: [iac-core]
        desc: |
          Caddy in front of the API: automatic TLS (1.2 minimum, 1.3 preferred), HSTS,
          basic rate limiting (doc 03's reverse-proxy "configuration must"), and the
          real client IP forwarded to the API for audit logging. The API runtime is
          never exposed directly.
        criteria:
          - "Caddy terminates TLS automatically and forwards the real client IP"
          - "HSTS is enabled; the API runtime is not directly reachable"
          - "basic rate limiting is configured at the proxy"
      - title: "Secrets backend provisioning"
        labels: [iac]
        blockedBy: [iac-core]
        desc: |
          Provision the secrets backend chosen in Phase 0 and wire runtime secret
          injection — nothing baked into images, nothing committed.
        criteria:
          - "the chosen secrets backend is provisioned by IaC"
          - "all runtime secrets are injected from it, verified by a smoke check"
      - title: "Automated backup scheduling"
        labels: [iac]
        blockedBy: [iac-core]
        desc: |
          Provision the schedule that drives the independent logical-backup tier: a
          systemd timer (or DO Function) that invokes `kura backup --local` on a
          regular cadence. The command itself is built in Phase 3 (`cli-backup`); this
          task provisions the timer, ensures the backups bucket and its append-only
          credential are wired, and confirms the backup encryption key is sourced from
          the secrets backend. DO's built-in Managed Postgres backups stay enabled in
          parallel for fast operational PITR — this tier is the separate-region,
          separate-credential, compromise-resilient copy.
        criteria:
          - "a scheduled job invokes `kura backup` on a documented cadence"
          - "the job uses the append-only backups-bucket credential and a secrets-sourced encryption key"
          - "DO managed backups remain enabled alongside the independent tier"
      - title: "Monitoring and alerting baseline"
        ref: iac-monitoring
        labels: [iac]
        blockedBy: [iac-core]
        desc: |
          Doc 03 provisioning step 11 — alerts on auth failures, database errors, and
          unusual API patterns — is part of the Definition of Done, not optional
          polish. Provision the baseline: DO native alert policies for infrastructure
          signals (droplet CPU/memory/disk, Managed Postgres health), plus an
          alerting consumer of the Phase 1 audit stream / Phase 2 audit-stream
          endpoints for application-level signals (auth-failure rate, authz-denial
          spikes). The audit subsystem already emits auth events distinctly, so the
          app-level alerting is a consumer, not new instrumentation. Keep it
          proportionate to the SMB tech-owner handoff target — alerts that route
          somewhere a human actually sees.
        criteria:
          - "infrastructure alert policies are provisioned by IaC (droplet + Managed Postgres health)"
          - "an alerting consumer fires on auth-failure / authz-denial patterns from the audit stream"
          - "alerts route to a configured destination; the `smoke-complete` monitoring check can verify them"
      - title: "Static IaC policy tests"
        ref: iac-policy
        labels: [iac, testing]
        blockedBy: [iac-core]
        desc: |
          Encode doc 03's "what not to deploy without" gates as static policy checks
          (tflint / Conftest): no public DB port, buckets private, TLS everywhere,
          no public SSH, and the audit-log bucket's immutability posture. On DO Spaces
          that posture is NOT Object Lock (Spaces has none) — it is versioning enabled
          plus a bucket policy denying object/version deletion and versioning-disable.
          The static check asserts exactly that achievable posture; true WORM is the
          Heavily-Regulated (AWS/GCP) tier. These run per-commit in CI, free, and
          assert the security posture without deploying anything.
        criteria:
          - "each doc-03 deployment gate has a corresponding static policy check"
          - "the audit-log bucket check asserts versioning + deny-delete policy, not Object Lock"
          - "the checks run in per-commit CI and fail on a deliberately broken config"
      - title: "terraform plan snapshot tests"
        labels: [iac, testing]
        blockedBy: [iac-core]
        desc: |
          Snapshot the plan output for a set of representative per-client configs, so
          a templating change that unexpectedly alters the plan fails CI. Free, fast,
          per-commit — catches templating regressions without touching real DO.
        criteria:
          - "plan snapshots exist for representative configs"
          - "an unintended templating change fails the snapshot test in CI"

  - title: "Phase 7 — Per-client deployment scaffold (kura init)"
    ref: phase-7
    labels: [phase-7, scaffold]
    blockedBy: [phase-6]
    desc: |
      The thin per-client deployment repo and the command that materializes it.
      Per-client repos are NOT forks of Kura — they are thin: a schema manifest, the
      per-client config, the instantiated IaC, a pinned Kura version, and a
      deployment README. They are named per client and handed off. The scaffold
      TEMPLATE lives inside the `kura` repo so it is versioned and tested with Kura.
    children:
      - title: "Embedded scaffold template"
        ref: scaffold-template
        labels: [scaffold]
        desc: |
          The template for a deployment repo, embedded in the `kura` binary
          (embed.FS): a starter schema manifest, a per-client config file, the
          instantiated DO IaC from Phase 6, a pinned Kura version, and a deployment
          README written for the SMB tech owner. Small enough to be comprehensible at
          handoff; "configuration is code" — the repo can rebuild the system.
        criteria:
          - "the embedded template contains manifest, config, IaC, pinned version, and README"
          - "the template is small and readable — no Kura application source is forked into it"
      - title: "kura init <name> command"
        labels: [scaffold, cli, tdd]
        blockedBy: [scaffold-template]
        desc: |
          `kura init <name>` materializes the embedded template into a fresh
          deployment repo, named for the client, with the Kura version pinned. This is
          the start of every engagement's build week — fill the manifest, set the
          config, run the generator.
        criteria:
          - "`kura init <name>` produces a complete, named deployment repo"
          - "the generated repo pins a specific Kura version"
      - title: "Scaffold output tested by Kura CI"
        labels: [scaffold, testing, tdd]
        blockedBy: [scaffold-template]
        desc: |
          Kura's own CI runs `kura init` and then validates the output: the manifest
          parses, the config is complete, the IaC passes the static policy checks and
          the `terraform plan` snapshot. The scaffold can never silently rot.
        criteria:
          - "CI generates a scaffold and validates manifest + config + IaC policy + plan snapshot"
          - "a regression in the scaffold template fails Kura's CI"

  - title: "Phase 8 — Testing infrastructure, release, and docs"
    ref: phase-8
    labels: [phase-8, testing, docs]
    blockedBy: [phase-3, phase-6, phase-7]
    desc: |
      Complete the tiered testing strategy, the release process, and the agent-facing
      documentation. Per-commit checks (unit, containerized Postgres, static IaC
      policy, plan snapshots) have been wired in as their phases landed; this phase
      adds the expensive real-DO end-to-end tier and finishes the docs.
    children:
      - title: "Complete the kura smoke suite"
        ref: smoke-complete
        labels: [testing, tdd]
        desc: |
          Finish the smoke suite begun in Phase 2 to cover doc 03's provisioning
          steps 9-11: end-to-end auth, audit, PII detection, and LLM-gateway flows,
          plus backup-restore (an actual restore to a throwaway target) and
          monitoring/alerting checks. This suite is the shared artifact for CI, the
          staging environment, and the provisioning agent's Definition of Done.
        criteria:
          - "the suite covers auth, audit, PII, LLM-gateway, backup-restore, and monitoring"
          - "backup-restore performs and verifies an actual restore"
      - title: "Per-release ephemeral real-DO end-to-end pipeline"
        labels: [testing]
        blockedBy: [smoke-complete]
        desc: |
          A release-cadence pipeline (not per-commit): in a Nobedan-owned test DO
          account, `terraform apply` -> `kura smoke` -> `terraform destroy`. This is
          the real last-mile gate — does the IaC stand up against DO's actual API, are
          pgaudit/pgcrypto really loadable, does Caddy really get certs, does OAuth
          really complete. Requires CI secrets (test DO token, Tailscale auth key,
          test Anthropic key) and a dedicated test Google Workspace domain.
        criteria:
          - "the pipeline applies, smokes, and destroys a real DO deployment on the release cadence"
          - "a dedicated test Google Workspace domain is configured for the OAuth path"
          - "a deliberately broken release is caught by the pipeline"
      - title: "Optional: long-lived staging / reference deployment"
        labels: [testing]
        blockedBy: [smoke-complete]
        desc: |
          A permanent reference deployment in a Nobedan DO account. Unlike the
          ephemeral e2e (always clean-install), this tests the UPDATE/migration path,
          and doubles as a demo environment and a Nobedan dogfooding target. Optional
          — decide whether the standing cost is worth it.
        criteria:
          - "a standing deployment exists and CI exercises the update/migration path against it"
      - title: "Agent-facing documentation"
        labels: [docs]
        desc: |
          Complete the docs/ tree begun in Phase 0, written for agents: machine
          interface (`--json`, exit codes, `agent-context`), concepts (identity,
          Cedar/IR, the manifest, PII handling), getting-started, and recipes
          (provisioning, the quarterly access review, incident triage). The README
          addresses agents directly, as `job`'s does.
        criteria:
          - "docs/ covers machine-interface, concepts, getting-started, and recipes"
          - "the README points agents to docs/ and the CLI guidelines"
      - title: "Engagement workflow guide"
        labels: [docs]
        desc: |
          A guide for the consultant/agent running an engagement: how Kura fits the
          3-week sprint, how to write a schema manifest, `kura init`, provisioning
          with the IaC baseline, running `kura smoke` as the Definition of Done, and
          handoff. The operational complement to the strategic playbook in the
          `nobedan` repo's `template/data-storage/02-for-nobedan.md`.
        criteria:
          - "the guide walks an engagement end-to-end from kura init to handoff"
      - title: "Open-source release and versioning process"
        labels: [docs, foundation]
        desc: |
          The process for cutting a Kura release: semantic version tagging of the Go
          module (deployment repos pin a version), changelog discipline, and the
          public-repo hygiene appropriate to an open-source security project (issue
          templates, security policy, contribution guide).
        criteria:
          - "a documented, repeatable release process exists with semver tagging"
          - "open-source repo hygiene files are in place (security policy, contributing, issues)"
```
