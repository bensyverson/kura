# Multi-IdP identity layer — full rearchitecture

- **Date:** 2026-05-18
- **Author:** Ben Syverson (with Claude)
- **Status:** Draft — pending approval before `job import`
- **Supersedes:** Phase 2 task `iTelH` ("Google Admin Directory IdP client") — that task gets cancelled when this plan is imported; its work is absorbed into Phase F below, reshaped as one implementation of a generalized directory interface. iTelH's three acceptance criteria are preserved verbatim on the successor tasks: the first two land on `f-google` (the Google directory client itself), the third (end-to-end IdP-mismatch detection against a real Workspace account) lands on `h-google` (the multi-IdP smoke test).

## Why

Kura today is Google-Workspace-coupled in several places:

- `internal/server/google.go` imports `golang.org/x/oauth2/google` and `google.golang.org/api/idtoken` directly.
- The OAuth seam is named `GoogleAuthenticator`, not a generic identity-provider interface.
- `identity.Principal.Domain` and `identity.DomainTrust` assume the Google-specific `hd` (hosted-domain) claim is what identifies a tenant. There is no equivalent claim in standard OIDC; other IdPs use `tid` (Microsoft Entra), issuer URL (Zitadel, Keycloak realms, Okta orgs), etc.
- The next Phase 2 task is literally "Google Admin Directory IdP client" — a Google-proprietary directory API.

Three reasons to fix this proactively rather than after a non-Google client appears:

1. **Pre-launch.** Per project CLAUDE.md, Kura has zero users and "we NEVER need to consider backward compatibility." The window to change identity types freely closes the moment Kura is deployed in earnest.
2. **Microsoft Entra is ~50% of the SMB IdP market.** Locking to Google Workspace excludes a large fraction of the target audience for any consultant using Kura.
3. **Two implementations validate the abstraction.** One implementation is just code; two is how you discover what's truly IdP-specific vs. what merely felt that way. The Microsoft adapter forces the abstraction to be real.

A practical fourth: the **kura-template** plan (see `/Users/ben/git/kura-template/project/2026-05-18-engagement-starter-plan.md`) hinges on a "vendor-neutral OIDC" pitch that is hollow until Kura itself is vendor-neutral.

## What changes (architecture, before/after)

### Today

```
identity.Principal{Type, ID, Email, Domain}              // Domain = Workspace domain
identity.DomainTrust{FirmDomain, ClientDomains, ...}     // keyed by Workspace domain
identity.IdPDirectory                                    // already a generic interface
server.WorkspaceIdentity{Email, Domain}                  // Google Workspace identity
server.GoogleAuthenticator                               // interface, but Google-named
server.googleAuthenticator                               // concrete Google OAuth + id_token
```

### After

```
identity.Principal{Type, ID, Email, Tenant}              // Tenant is per-IdP opaque key
identity.TenantTrust{FirmTenant, ClientTenants, ...}     // generic tenant trust
identity.IdPDirectory                                    // unchanged interface; multiple impls
server.VerifiedIdentity{Email, Tenant, Issuer}           // generic verified identity
server.IdentityProvider                                  // generic IdP interface
server.googleIdP                                         // Google Workspace implementation
server.microsoftIdP                                      // Microsoft Entra implementation
server.oidcIdP                                           // Generic OIDC (Zitadel, Keycloak, ...)
server.googleDirectory                                   // Google Admin Directory impl of IdPDirectory
server.microsoftDirectory                                // Microsoft Graph impl of IdPDirectory
server.noopDirectory                                     // For generic OIDC: always-active fallback
```

### What "Tenant" means per IdP

| IdP | Tenant claim | Example value |
|---|---|---|
| Google Workspace | `hd` | `example.com` |
| Microsoft Entra | `tid` | `72f988bf-86f1-...` (UUID) |
| Generic OIDC | issuer URL | `https://auth.example.com/realms/myrealm` |

The `TenantTrust` config becomes IdP-aware: deployments configure `FirmTenant` as either a Workspace domain, an Entra tenant UUID, or a Zitadel/Keycloak issuer URL depending on `KURA_IDP`.

## Locked decisions

| Decision | Choice | Rationale |
|---|---|---|
| Scope | Full rearchitecture — Google + Microsoft + generic OIDC implementations | Two impls test the abstraction; three covers ~95% of SMB identity landscape. Generic OIDC future-proofs the self-hosted / EU / open-source IdP case. |
| OIDC library | `coreos/go-oidc/v3` for Microsoft + generic; keep `google.golang.org/api/idtoken` for Google | `coreos/go-oidc` is the mature standard for OIDC discovery + JWKS verification in Go. Google's `idtoken` library is faster for the Google path because it bakes in Google's keys. Use the right tool per IdP. |
| Microsoft testing | Free **Microsoft 365 Developer Program** tenant | Provides 25 users, groups, realistic shape. Ben's existing M365 business account confirms the code works in a "real" tenant. |
| Config selection | `KURA_IDP=google\|microsoft\|oidc` env var | One IdP active per deployment. Multi-IdP in a single deployment is out of scope for v1 — a deployment serves one client, who has one IdP. |
| Directory abstraction | Three implementations: `googleDirectory`, `microsoftDirectory`, `noopDirectory` | The first two cover Workspace and Entra account-status checks. `noop` reports `AccountActive` for generic OIDC where there is no upstream directory to check — documented limitation, acceptable for OSS providers used in dev/internal scenarios. |
| Naming | `Tenant` (not `Realm`, `Org`, or `Workspace`) | Most neutral term; reads correctly across all three implementations. |
| Multi-tenant per IdP | Out of scope | A Kura deployment trusts a fixed set of tenants per its `TenantTrust` config; it does not dynamically discover or onboard tenants. v1 covers single-IdP, multi-tenant-in-config. |

## Explicitly out of scope (for v1)

- SAML support. OIDC covers every IdP we care about for SMB.
- LDAP / Active Directory on-prem connectors.
- SCIM provisioning (Kura is consumer-of-identity, not source-of-truth).
- Just-in-time user creation on first sign-in (existing manifest-driven model stays).
- Multi-IdP in a single deployment (one IdP per deployment).
- Microsoft personal accounts (live.com, outlook.com) — Entra org accounts only.
- Okta-specific or Auth0-specific adapters — covered by generic OIDC.

## Open questions for after approval

- Whether to rename `IdPDirectory` to just `Directory` for symmetry with `IdentityProvider`. Leaning yes — included in Phase F.
- Whether `Issuer` belongs on `VerifiedIdentity` separately from `Tenant`, or whether tenant + issuer can be collapsed for the generic OIDC case. Leaning keep both — issuer is useful for audit-log forensics even when tenant == issuer.
- Library pin for `coreos/go-oidc` — current stable is v3. Pin in `go.mod` during Phase C.

## Plan

```yaml
tasks:
  - title: Multi-IdP identity layer — full rearchitecture
    desc: |
      Generalize Kura's identity layer to support Google Workspace,
      Microsoft Entra, and generic OIDC providers. Renames Google-specific
      types in the core, extracts the OAuth seam into a vendor-neutral
      IdentityProvider interface, adds two new IdP implementations, adds
      a Microsoft Graph directory client alongside the Google Admin
      Directory client, and plumbs IdP selection through config.

      Supersedes Phase 2 task iTelH ("Google Admin Directory IdP client")
      — the directory work is absorbed into Phase F as one of three
      directory implementations.

      Pre-launch refactor: no backward compatibility concerns per project
      CLAUDE.md. Aim to complete before Phase 3 (CLI) and Phase 4
      (dashboard) start materially depending on the current identity
      types.
    labels: [identity, oidc, refactor]
    children:

      - title: Phase A — Generalize core identity types
        ref: idp-phase-a
        labels: [phase-a, identity, refactor]
        desc: |
          Mechanical-renaming heavy. Rename `Principal.Domain` to
          `Principal.Tenant` throughout. Rename `DomainTrust` to
          `TenantTrust`, with fields `FirmTenant`, `ClientTenants`,
          `AdminEmails`. Rename `ErrUntrustedDomain` to
          `ErrUntrustedTenant`. Strip Google-specific commentary from
          identity package doc comments — replace with IdP-agnostic
          language naming the three supported families.
        children:
          - title: Rename Principal.Domain → Principal.Tenant; update Valid() and tests
            ref: a-principal
            labels: [identity, tdd]
            desc: |
              TDD red/green: update principal_test.go expectations first
              (field name, validation error messages), confirm reds,
              then rename in principal.go. The semantic doesn't change
              — only the field name and the doc comment that calls it
              "Workspace domain" → "IdP tenant identifier".
          - title: Rename DomainTrust → TenantTrust; rename methods and tests
            ref: a-trust
            blockedBy: [a-principal]
            labels: [identity, tdd]
            desc: |
              workspace.go → tenant_trust.go. DomainTrust.Principal stays
              functionally identical for now — it still receives an email
              and a tenant key, decides FirmTenant vs ClientTenants vs
              untrusted. Comments updated to drop Google specificity.
              Tests in workspace_test.go → tenant_trust_test.go.
          - title: Rename ErrUntrustedDomain → ErrUntrustedTenant; sweep references
            ref: a-err
            blockedBy: [a-trust]
            labels: [identity, refactor]
            desc: |
              grep + replace across cmd/, internal/. Any consumer that
              switched on the error or wrapped its message needs updating.
              Expected radius: small — this is a fresh codebase and the
              error is checked in maybe 1-2 places.

      - title: Phase B — Extract the IdP seam in the server package
        ref: idp-phase-b
        labels: [phase-b, server, refactor]
        blockedBy: [idp-phase-a]
        children:
          - title: Rename WorkspaceIdentity → VerifiedIdentity; add Issuer field
            ref: b-verified
            labels: [server, tdd]
            desc: |
              `VerifiedIdentity{Email, Tenant, Issuer}`. Issuer is the
              OIDC issuer URL (e.g. https://accounts.google.com,
              https://login.microsoftonline.com/<tid>/v2.0,
              https://auth.example.com/...). Useful for audit-log
              forensics and for the generic-OIDC tenant key. Update
              oauth.go and oauth_test.go.
          - title: Rename GoogleAuthenticator interface → IdentityProvider; sweep callers
            ref: b-iface
            blockedBy: [b-verified]
            labels: [server, tdd]
            desc: |
              Interface methods unchanged: AuthCodeURL(state) string;
              Exchange(ctx, code) (VerifiedIdentity, error). Move the
              interface declaration into a new file
              `internal/server/idp.go` so it sits separately from any
              one implementation. Update oauth.go's handler field name
              from `google` to `idp`. Tests stay green on the Google
              path.
          - title: Move googleAuthenticator → googleIdP in internal/server/idp_google.go
            ref: b-google
            blockedBy: [b-iface]
            labels: [server, refactor]
            desc: |
              Rename the struct, rename the file, update the constructor
              to NewGoogleIdP. Logic untouched. Existing oauth_test.go
              fakes continue to satisfy the renamed IdentityProvider
              interface unchanged.

      - title: Phase C — Microsoft Entra IdP implementation
        ref: idp-phase-c
        labels: [phase-c, server, microsoft]
        blockedBy: [idp-phase-b]
        children:
          - title: Add coreos/go-oidc v3 dependency
            ref: c-dep
            labels: [deps]
            desc: |
              Add github.com/coreos/go-oidc/v3 to go.mod. This library
              is the mature standard for OIDC discovery + JWKS-based
              id_token verification in Go. Used for both Microsoft and
              generic-OIDC implementations. Per project policy, dependency
              addition needs explicit user nod — calling that out: this
              is the one new dependency this plan introduces. (golang.org/x/oauth2
              is already vendored.)
          - title: ADR — choose coreos/go-oidc for non-Google IdPs
            ref: c-adr
            blockedBy: [c-dep]
            labels: [adr, deps]
            desc: |
              docs/decisions/ — document the choice. Alternatives:
              zitadel/oidc (good but more opinionated), hand-rolled JWKS
              verification (re-implements solved problems). coreos/go-oidc
              wins on maturity and minimality. Approved-by: Ben Syverson.
          - title: Implement microsoftIdP in internal/server/idp_microsoft.go
            ref: c-impl
            blockedBy: [c-adr]
            labels: [server, microsoft, tdd]
            desc: |
              Discovery URL: https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration.
              Constructor takes ClientID, ClientSecret, RedirectURL, and
              either a specific TenantID or "common" for multi-tenant.
              Exchange yields VerifiedIdentity{Email: preferred_username
              or email claim, Tenant: tid claim, Issuer: issuer claim}.
              Reject tokens missing tid (single-tenant deployments must
              not accept anonymous /common tokens). TDD: fake token
              verifier in tests; integration test gated behind env var.
          - title: Document Microsoft sign-in setup in docs/content/docs/
            ref: c-docs
            blockedBy: [c-impl]
            labels: [docs, microsoft]
            desc: |
              How to register an app in Entra admin center, what
              redirect URI to use, where to find ClientID/ClientSecret/
              TenantID, what permissions to grant (User.Read minimum).
              Link to the Microsoft 365 Developer Program for free dev
              tenant access.

      - title: Phase D — Generic OIDC IdP implementation
        ref: idp-phase-d
        labels: [phase-d, server, oidc]
        blockedBy: [idp-phase-b, c-dep]
        children:
          - title: Implement oidcIdP in internal/server/idp_oidc.go
            ref: d-impl
            labels: [server, oidc, tdd]
            desc: |
              Constructor takes IssuerURL, ClientID, ClientSecret,
              RedirectURL. Uses coreos/go-oidc Provider for discovery
              and Verifier for id_token validation. Email from `email`
              claim; Tenant = IssuerURL (the closest universal proxy
              for tenancy in vanilla OIDC); Issuer = IssuerURL.
              Reject tokens without email_verified=true. TDD: fake
              issuer with a local test JWKS server.
          - title: Verify against Zitadel and Keycloak in dev
            ref: d-verify
            blockedBy: [d-impl]
            labels: [oidc, validation]
            desc: |
              Spin up Zitadel and Keycloak in docker-compose locally,
              register a Kura app in each, sign in end-to-end. Confirms
              the abstraction works for two distinct generic-OIDC
              vendors. Document gotchas in docs/.
          - title: Document generic OIDC setup
            ref: d-docs
            blockedBy: [d-verify]
            labels: [docs, oidc]
            desc: |
              docs/ — generic OIDC config recipe. Examples for Zitadel,
              Keycloak, Okta (org-as-tenant), Auth0 (tenant-as-issuer).
              Spell out the IssuerURL-as-Tenant tradeoff and what it
              means for TenantTrust configuration.

      - title: Phase E — Config plumbing and IdP selection
        ref: idp-phase-e
        labels: [phase-e, config, cli]
        blockedBy: [idp-phase-c, idp-phase-d]
        children:
          - title: Add KURA_IDP env var and per-IdP config groups
            ref: e-env
            labels: [config]
            desc: |
              KURA_IDP ∈ {google, microsoft, oidc}; required. Per-IdP
              groups: GOOGLE_OAUTH_CLIENT_ID/SECRET (existing), MICROSOFT_
              TENANT_ID/CLIENT_ID/CLIENT_SECRET, OIDC_ISSUER_URL/CLIENT_ID/
              CLIENT_SECRET. Shared: KURA_OAUTH_REDIRECT_URL. Fail fast
              with clear error on missing required vars for the selected
              IdP.
          - title: Wire IdP construction in cmd/kura/serve.go
            ref: e-wire
            blockedBy: [e-env]
            labels: [cli, server, tdd]
            desc: |
              Switch on KURA_IDP to construct the right IdentityProvider.
              Update serve_test.go to cover each branch. The OAuth
              handler stays IdP-agnostic — it gets one IdentityProvider
              and uses it. No conditional logic leaks into handlers.
          - title: Update TenantTrust config to be IdP-aware in docs
            ref: e-trust-docs
            blockedBy: [e-wire]
            labels: [docs, config]
            desc: |
              Per-IdP examples of what FirmTenant and ClientTenants look
              like: domain for Google, UUID for Microsoft, issuer URL
              for OIDC. Make the docs show three side-by-side recipes so
              operators can copy the right one.

      - title: Phase F — Generalize the directory abstraction
        ref: idp-phase-f
        labels: [phase-f, directory, supersedes-iTelH]
        blockedBy: [idp-phase-a]
        desc: |
          Absorbs and supersedes Phase 2 task iTelH. The IdPDirectory
          interface already exists; this phase adds three implementations
          and reframes the work as part of the IdP-agnostic story.
        children:
          - title: Rename IdPDirectory → Directory (symmetry with IdentityProvider)
            ref: f-rename
            labels: [identity, refactor]
            desc: |
              Cosmetic. Updates idp.go (rename or split), idp_test.go,
              and any consumers. Worth doing while the surface is small.
              FakeIdPDirectory → FakeDirectory.
          - title: Implement googleDirectory using Google Admin SDK Directory API
            ref: f-google
            blockedBy: [f-rename]
            labels: [directory, google, tdd]
            desc: |
              The work originally planned in iTelH, now framed as one
              Directory implementation. Service-account-based auth with
              domain-wide delegation; reads users.get to determine
              accountEnabled / suspended / not-found → AccountActive /
              AccountSuspended / AccountAbsent. Integration test gated
              behind env var; unit tests via Fake.
            criteria:
              - the client reports active/suspended/absent status for a Workspace account
              - it authenticates with the Admin SDK using least-privilege scopes, documented in docs/
          - title: Implement microsoftDirectory using Microsoft Graph
            ref: f-microsoft
            blockedBy: [f-rename, c-impl]
            labels: [directory, microsoft, tdd]
            desc: |
              GET /users/{email}?$select=accountEnabled. App-only auth
              with User.Read.All application permission (admin consent
              once during app registration). Maps accountEnabled true →
              AccountActive, false → AccountSuspended, 404 → AccountAbsent.
              Integration test against M365 Developer Program tenant.
          - title: Implement noopDirectory for generic OIDC
            ref: f-noop
            blockedBy: [f-rename]
            labels: [directory, oidc]
            desc: |
              Always returns AccountActive. Generic OIDC has no standard
              directory API. Document this as a known limitation — the
              IdP-mismatch detection feature is unavailable for generic
              OIDC deployments and must be compensated for at the IdP
              side (e.g. shorter token lifetimes, IdP-side revocation).
          - title: Wire directory selection alongside IdP selection in serve
            ref: f-wire
            blockedBy: [f-google, f-microsoft, f-noop, e-wire]
            labels: [cli, server, tdd]
            desc: |
              KURA_IDP=google → googleDirectory; microsoft →
              microsoftDirectory; oidc → noopDirectory. Separate env
              vars for each directory's credentials (Google service
              account JSON path; Microsoft uses the same client creds
              as the IdP).
          - title: Cancel original iTelH task with a note pointing to f-google
            ref: f-housekeeping
            blockedBy: [f-google]
            labels: [housekeeping]
            desc: |
              `job cancel iTelH -m "Superseded by multi-IdP rearchitecture
              plan; directory work landed as f-google."` Keeps the Phase
              2 history clean and connects the old plan to the new.

      - title: Phase G — Docs sweep
        ref: idp-phase-g
        labels: [phase-g, docs]
        blockedBy: [idp-phase-e, idp-phase-f]
        children:
          - title: Rewrite docs/content/docs/concepts/identity.md
            ref: g-identity-doc
            labels: [docs]
            desc: |
              Strip Google-specific framing. Present the three-IdP model
              (Google / Microsoft / generic OIDC), the Tenant abstraction,
              the TenantTrust mapping. Side-by-side config examples.
          - title: Update docs/content/docs/concepts/server.md
            ref: g-server-doc
            blockedBy: [g-identity-doc]
            labels: [docs]
            desc: |
              Server overview reflects vendor-neutrality. Sign-in flow
              section becomes IdP-agnostic with per-IdP appendices.
          - title: Add a docs/getting-started page per IdP
            ref: g-getting-started
            blockedBy: [g-identity-doc]
            labels: [docs]
            desc: |
              Three short recipes: "Run Kura with Google Workspace",
              "Run Kura with Microsoft Entra", "Run Kura with self-hosted
              OIDC (Zitadel example)". Each one is a copy-paste config
              + walkthrough. These are the pages a new operator lands on.

      - title: Phase H — End-to-end multi-IdP smoke test
        ref: idp-phase-h
        labels: [phase-h, validation]
        blockedBy: [idp-phase-g]
        children:
          - title: Google Workspace sign-in end-to-end against real tenant
            ref: h-google
            labels: [validation, google]
            desc: |
              Confirm the rename hasn't regressed the Google path. Real
              Workspace sign-in, real directory lookup, real principal
              resolution, real audit-log entry. Includes the IdP-mismatch
              detection scenario carried forward from iTelH: a suspended
              upstream account still holding a Kura role is denied.
            criteria:
              - IdP-mismatch detection runs end-to-end against the real client
          - title: Microsoft Entra sign-in end-to-end against M365 Dev Program tenant
            ref: h-microsoft
            labels: [validation, microsoft]
            desc: |
              Sign Ben up for the Microsoft 365 Developer Program. Provision
              an Entra dev tenant. Register Kura as an app. Run full sign-in
              + directory lookup against fake users. This is the
              proof-of-vendor-neutrality.
          - title: Generic OIDC sign-in end-to-end against local Zitadel
            ref: h-oidc
            labels: [validation, oidc]
            desc: |
              docker-compose Zitadel locally; sign in end-to-end through
              Kura. Confirms generic OIDC works without code changes per
              vendor.
          - title: Document the multi-IdP test recipe in docs/
            ref: h-recipe
            blockedBy: [h-google, h-microsoft, h-oidc]
            labels: [docs, validation]
            desc: |
              Capture exactly how to reproduce each of the three smoke
              tests. This is how the next person (or future Claude
              session) validates after touching identity code.
```

## How to use this file

1. Review locked decisions + open questions; push back before importing.
2. From the kura repo, preview with `job import project/2026-05-18-multi-idp-identity.md --dry-run`.
3. Drop `--dry-run` to commit.
4. Run `job cancel iTelH -m "Superseded by multi-IdP plan; tracked as f-google"` (or leave that to task `f-housekeeping` to perform after `f-google` completes).
5. Begin execution with `job claim --next`.

## Risk and rollback

This is a fresh-codebase refactor with no users; rollback is `git revert`. The two non-trivial risks are:

- **The Microsoft path requires a real Entra tenant for integration testing.** Mitigated by the M365 Developer Program (free). Until that tenant is registered, Phase H Microsoft validation is blocked, but no other phase is.
- **The `coreos/go-oidc` dependency is the one new external import.** It is mature, widely used, MIT-licensed; risk is low. Per project policy this needs an explicit nod from the user — captured as `c-dep`.
