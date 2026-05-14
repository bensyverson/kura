# Kura — Architecture & Design Rationale

**Audience:** agents (and humans) working on Kura. This is the *why* behind the
*what*. The build plan (`2026-05-14-kura-build-plan.md`) says what to build; the CLI
guidelines (`2026-05-14-cli-design-guidelines.md`) say how the CLI behaves; this doc
says why the system is shaped the way it is — and which roads were deliberately not
taken.

**How to use it:** before changing a structural decision, find it here. If a choice
looks inconvenient and you are tempted to simplify it, the rationale and the rejected
alternative are written down for exactly that moment. If you make a new structural
decision, add it here.

---

## What Kura is (in brief)

A single open-source Go binary, `kura`, that provisions and operates a secure,
audited, PII-aware data store for SMB consulting engagements. It implements the
strategic playbook (`02-for-nobedan.md`) and reference architecture
(`03-for-agents.md`) in the `nobedan` repo's `template/data-storage/` directory. See
the build plan for the full component breakdown.

---

## The shape, and why

### One binary, four faces, one core

The product is `internal/` — the **core enforcement library**: Cedar authorization,
audit logging, PII detection/masking, field-level encryption, data access. Four thin
adapters sit over it: `kura serve` (the remote HTTP API), the CLI, `kura dashboard`
(a local web app), and `kura mcp`.

**Why:** three-plus surfaces that must stay behaviorally identical will drift if each
holds its own logic. One core with thin adapters keeps them in lockstep. This is not
theoretical — `job` (`~/git/jobs`) proves the pattern at smaller scale: its CLI and
web dashboard both call `internal/job` with no API-layer indirection. Kura adds a
real API layer and a fourth adapter, but the structure is the same.

**Rule that follows:** logic belongs in `internal/`. An adapter file that holds a
policy decision, an audit write, or a masking rule is a bug.

### The core is the gate (not "the API is the only gate")

This is a deliberate **deviation from `03-for-agents.md` principle 3**, which says
"the API is the only gate." In Kura, enforcement lives in the *core library*; the API
is its primary public expression but not the only path — the CLI's `--local` mode and
provisioning call the core directly.

**Why this is an upgrade, not a weakening:** principle 3 already reserves direct
database access "for the agent during provisioning and the tech owner during incident
response." Today that path is raw, unaudited `psql`. Kura's `--local` is that same
break-glass path — but it goes *through the core*, so it is still Cedar-checked, still
audited, still masked. Kura replaces the reference architecture's one unaudited hole
with an instrumented tool.

**Constraint this imposes:** enforcement must be airtight in the core library, not in
the API handlers. The Phase 1 "gate" task makes the sequence
authn → authz → access → mask → audit impossible to skip by construction, not by
convention.

### The CLI is remote-first; `--local` is break-glass

The primary CLI user is a local agent — Claude Code on a consultant's laptop —
operating a client's *remote* deployment. So `kura <verb>` is, by default, an HTTP
client of a remote `kura serve`. `--local` (direct core access, on-box) is the
break-glass exception: incident response when the server is down, and the narrow
provisioning window before the API is up.

**Alternatives rejected:**
- *CLI always library-direct* — does not fit the remote-primary use case at all.
- *CLI always over HTTP, including break-glass* — useless precisely when the server
  itself is the thing that is broken.

### The dashboard runs local — this is the decision most likely to be wrongly "fixed"

`kura dashboard` runs **locally**, loopback-bound, as just another HTTP client of the
remote API. It is *not* served by the remote `kura serve`.

**Why:** a remote web app drags XSS, CSRF, session, and template attack surface onto
the public internet. And the dashboard renders client PII (the data browser) — so an
XSS in a *remote* dashboard is an XSS *inside the security boundary*, executing in an
authenticated admin's session. That is the worst single vulnerability this system
could have. Running the dashboard locally means that entire vuln surface executes on
one user's localhost, never a shared public host — and it lets `kura serve` stay
purely a JSON API (see next section).

**Cost, and why it is acceptable:** distribution friction — every dashboard user needs
the `kura` binary. But the dashboard audience is tiny (1–3 admins per client) and they
already have the binary. There is no mobile target; custom apps cover that later.

**Alternatives rejected:** a remote web app (attack surface, above). The
quarterly-access-review-by-emailed-link workflow was specifically considered — it
mildly favors a remote page — and rejected; the access review runs in the local
dashboard.

**If you are tempted to make the dashboard remote "for convenience": don't.** Re-read
this section.

### `kura serve` is API-only

Follows directly from the dashboard being local. The remote surface is *just* the
JSON API (plus, possibly, an OAuth callback). This is the smallest possible public
attack surface — it honors `03-for-agents.md` principle 6 ("the only public endpoints
are the API and the OAuth callback") with no asterisk — and it makes a future SOC 2
audit story materially simpler.

### MCP is local-proxy by default

`kura mcp` runs as a local stdio-transport proxy to a remote server by default;
remote-served HTTP is an option. The consumer of MCP is the *client's own agents*
post-handoff.

**Why the default differs from the dashboard's:** MCP-over-HTTP is structurally close
to the API — JSON-RPC, typed, token auth. It does *not* carry the web app's
XSS/CSRF/session baggage. So a remote MCP endpoint is a *small, uniform* surface
addition, unlike a remote web app. The decision is therefore "by consumer," not
dogmatic: local proxy for a consultant's own agent, remote-served when a client's
post-handoff agents need it.

### Per-client deployments are thin repos that depend on the Kura module

A per-client deployment repo is **not** a fork of Kura. It is thin: a schema manifest,
the per-client config, the instantiated IaC, a pinned Kura version, and a deployment
README. Kura itself is a versioned Go module + binary — one source of truth. The
thin-repo scaffold lives *inside* the `kura` repo (embedded), is materialized by
`kura init`, and is tested by Kura's own CI.

**Why not "clone the template and modify":** that makes every per-client repo a fork.
With N clients you would cherry-pick Kura improvements across N divergent forks
forever, and the handoff artifact would be a large Go application the SMB tech owner
cannot comprehend. With the thin-repo model, a Kura improvement is a version bump, and
the handoff artifact is small and readable. `03-for-agents.md` principle 9
("configuration is code, the system can be rebuilt from the repo") still holds — the
thin repo plus the pinned version *is* the full spec.

### Declarative IaC, not `deploy.sh`

The DigitalOcean Standard-Regulated deployment is declarative IaC. Terraform (not
Pulumi) — settled in Phase 0; see "Decisions already closed" below.

**Why not a shell script:** an imperative script calling `doctl` is fragile,
non-idempotent, and effectively untestable. Declarative IaC is idempotent, its
plan/apply model maps onto `02-for-nobedan.md`'s "read the agent's plan before it
runs," and `terraform plan` output is itself a testable artifact (the build plan uses
plan-snapshot tests).

### The schema manifest is the keystone

One per-client manifest file — entities, relationships, PII-sensitivity tags — drives
*four* surfaces: the dashboard's data browser, the CLI's `query`/`show` verbs, the MCP
data tools, and the Cedar policy IR (its roles × entities × categories × actions axes
come from the manifest).

**Why this matters:** it is the answer to "how instrumented can a new engagement be?"
With the manifest as the single input, a new engagement's entire usability layer
collapses to "write the manifest." Protect this property — resist building
entity-specific code into any of the four surfaces.

---

## Deliberate deviations from the reference architecture

Kura implements `03-for-agents.md`, but departs from it in two reasoned ways. **These
are intentional. Do not "correct" them back.**

1. **"The core is the gate" vs. principle 3's "the API is the only gate."** Covered
   above. The deviation upgrades the break-glass path from raw `psql` to an audited,
   masked `--local` tool.

2. **A tested IaC baseline vs. "the agent generates artifacts each time."**
   `03-for-agents.md` deliberately ships no Dockerfiles or Terraform — "the
   architecture is durable, the artifacts are disposable," the agent regenerates per
   engagement. Kura's refinement: for the DigitalOcean Standard-Regulated path
   *specifically* — the one run repeatedly — maintain a tested, known-good baseline.
   Regenerating from spec every time is wasteful and risks subtly divergent
   deployments. This does not violate the doc's intent: the "don't pin artifacts"
   advice is about keeping the *spec* portable. Heavily-Regulated (AWS/GCP) stays
   agent-generated, because those are rare.

---

## Decisions already closed

These were settled during design. The build plan's Phase 0 also carried five
architectural decisions (consultant authentication, the DigitalOcean secrets backend,
the Cedar policy-apply ceremony, the `agent-context` mechanism, Terraform vs. Pulumi)
— all five were resolved with the user before import; their rationales are recorded
in the corresponding Phase 0 tasks and are expanded into this section as those tasks
execute.

- **Kura is 100% open source.** Calling card for the consulting practice, and full
  auditability — which matters for a security product. Same logic as the Penumbra/FPP
  open-core strategy: the code is not the moat; the playbook and judgment are.
- **DigitalOcean Standard-Regulated is the happy path.** It is the default tier for
  any PII engagement (`02`/`03`). Kura ships this as the tested IaC baseline.
- **Two-tier model — Standard Regulated and Heavily Regulated.** Inherited from
  `02-for-nobedan.md`. Kura ships the Standard baseline; Heavily Regulated (AWS/GCP,
  customer-managed keys, private LLM paths) stays agent-generated per the reference
  architecture.
- **Structured viewer before structured builder.** The V1 Cedar UI is a *read-only
  structured viewer* over the policy IR. The eventual structured *builder* edits the
  same IR. The viewer ships the IR model and the IR-to-Cedar compile path, so it is a
  genuine baby-step — nothing is throwaway. Free-form Cedar authoring stays a repo/PR
  activity.
- **The consultant is a distinct Cedar principal type, authenticated against the
  firm's own Workspace.** The consultant is `Consultant`, not a guest in the client's
  Google Workspace. Authentication is Google OAuth against the consulting firm's own
  Workspace domain — named per-deployment in the client's config; Kura hardwires no
  firm identity. The client's config trusts that firm domain for the `Consultant`
  type only, separately from the client domain that maps to `User`/`Admin`. The
  consultant's agent acts *as* the consultant — `kura login` signs the consultant in
  against the firm domain and the agent uses that short-lived token; there is no
  per-agent principal in v1. **Why:** the firm (not the client) controls consultant
  offboarding, consultant actions are distinct in the audit log, and engagement-end
  is a config change (remove the firm-domain trust). Shapes `kura login`, the token
  model, and the Cedar principal schema (Phase 1 identity, Phase 2 server-auth). Full
  record in `docs/content/docs/concepts/identity.md`.
- **The Standard-Regulated secrets backend is Doppler.** Self-hosted Vault was
  rejected (too much ongoing ops for the SMB-tech-owner handoff target — it would rot
  post-handoff); cross-cloud AWS Secrets Manager was rejected (forces a second cloud
  account on a DO client, worse bootstrap). Doppler is low-ops, SOC 2-attested, does
  runtime injection, and holds only secrets (never PII), so the added-sub-processor
  surface is bounded. The Doppler account is client-owned — infra lives in the
  client's account, never the firm's — provisioned during the engagement and handed
  off with the stack. Applied by the Phase 1 secrets-manager abstraction and the
  Phase 6 secrets-provisioning task. Heavily-Regulated stays agent-generated and may
  differ. Full record in `docs/content/docs/concepts/secrets.md`.
- **v1 Cedar policy is loaded at deploy time — no live apply path.** The server
  loads its Cedar policy from the deployment repo at startup; changing policy means
  changing the repo and redeploying. There is no `kura policy apply` command and no
  watch-and-reload in v1. **Why:** v1's Cedar UI is a read-only viewer, so nothing on
  a running surface changes policy — a live apply path would solve a problem that
  does not exist yet. PR-gating comes for free (a repo change is a PR). The dedicated
  apply ceremony is revisited when the structured Cedar *editor* lands, decided then
  against real requirements. Full record in
  `docs/content/docs/concepts/policy.md`.
- **The Standard-Regulated IaC baseline uses Terraform, not Pulumi.** Deciding
  factor: the IaC ships in the thin per-client repo handed to an SMB tech owner, and
  declarative HCL is far more readable to a non-Go person than Pulumi Go code —
  "configuration is code" only helps if they can read it. Plan/apply also maps to the
  playbook's "read the agent's plan before it runs," and the IaC test strategy
  (tflint/Conftest, `terraform plan` snapshots) is already Terraform-shaped. Terraform
  is a separate tool, not a Go-module dependency, so it does not touch Kura's
  supply-chain surface. Scoped to Standard-Regulated; Heavily-Regulated stays
  agent-generated. Full record in `docs/content/docs/concepts/iac.md`.
- **Pragmatic minimalism on dependencies.** Aggressively avoid incidental and
  transitive dependencies — a smaller audit and supply-chain surface is a *security*
  posture for an open-source security product, not just aesthetics. But keep the
  load-bearing specialist libraries (Cobra, a Cedar engine, an OAuth library, an MCP
  SDK, the Postgres driver): re-implementing authorization, crypto, or protocol code
  is itself a security risk, and a hand-rolled authz evaluator is a far bigger danger
  than a vetted dependency.

---

## Threat model boundary

Inherited from `03-for-agents.md`. Stated here so adapters are not over-engineered for
threats outside the model.

**Designed against:** leaked credentials, insider error, misconfigured exposure,
departed-employee retention, and data drift into the LLM provider.

**Not designed against:** nation-state attackers, sophisticated insider collusion
(multiple authorized users coordinating), and extended denial-of-service campaigns.
Kura is built for confidentiality and integrity, not extreme availability.

---

## Open questions

Phase 0's five architectural decisions (consultant authentication model, DigitalOcean
secrets-backend default, Cedar policy-apply ceremony, the `agent-context` generation
mechanism, Terraform vs. Pulumi) were resolved with the user before import. Their
rationales live in the corresponding Phase 0 "Record & apply" tasks and are expanded
into the "Decisions already closed" section above as those tasks execute. No
structural decisions are currently open.

---

## Provenance

- **`job`** (`~/git/jobs`) — Ben Syverson's agent-native task CLI. Kura inherits its
  shared-core / thin-adapter structure and its agent-native CLI patterns.
- **"10 Principles for Agent-Native CLIs"** (trevinsays.com) — synthesized with
  `job`'s lessons into `2026-05-14-cli-design-guidelines.md`.
- **`nobedan` repo, `template/data-storage/`** — `02-for-nobedan.md` (the strategic
  playbook) and `03-for-agents.md` (the reference architecture) are the spec Kura
  implements; this doc records where and why Kura concretizes or deviates from them.
