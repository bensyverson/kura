---
title: Identity & principals
weight: 1
---

Every action in Kura is attributed to a **principal** — a real Cedar entity that the
audit log records and that Cedar policy reasons about. There is no "the CLI is
trusted" backdoor: the CLI, the HTTP API, the dashboard, and MCP all resolve a
principal and emit an audit event for every action.

This page records the **consultant authentication model** — a decision resolved
during design — and the Cedar principal schema that follows from it.

## The consultant authentication model

The consultant is a **distinct Cedar principal type** (`Consultant`), **not** a guest
in the client's Google Workspace.

Authentication is still Google OAuth, but a consultant signs in against the
**consulting firm's own Workspace domain** — whatever domain the firm operating the
engagement owns. A client's deployment config names that firm domain and trusts it
for the `Consultant` principal type *only* — separately from the client domain, which
maps to `User` and `Admin`. The firm domain is per-deployment configuration; Kura
hardwires no firm identity.

The consultant's agent acts **as** the consultant: `kura login` signs the consultant
in against the firm domain, and the agent uses that short-lived token. There is **no
separate per-agent principal in v1** — the human owns the session, and the audit log
attributes actions to them. Ending an engagement, or re-engaging, is a config change:
add or remove the firm-domain trust.

### Why

- **Offboarding control.** The consulting firm controls consultant offboarding, not
  the client. A consultant who leaves the firm loses access to *every* client
  deployment at once, through the firm's own Workspace — the client never has to act.
- **Distinct audit trail.** Consultant actions are a distinct principal type in the
  audit log, never blurred into the client's own users.
- **Engagement-end is declarative.** Re-engagement and disengagement are a trust-list
  edit in the deployment config, not an account-lifecycle dance in the client's
  directory.

> **Example.** The reference engagement is run by a firm on the domain
> `nobedan.com`, so a client deployment for that engagement trusts `nobedan.com` for
> `Consultant` and a consultant logs in as e.g. `alex@nobedan.com`. Any other firm
> configures its own domain instead — none of this is baked into Kura.

This decision shapes `kura login`, the short-lived token model, and the Cedar
principal schema. Its downstream implementation lands in the Phase 1 identity task and
the Phase 2 server-auth task.

## Cedar principal schema

The principal types Cedar reasons about. Roles, resource types, and actions are
layered on in Phase 1 (the identity and Cedar-IR tasks) and are driven by the
per-client schema manifest; this records only the **principal** taxonomy.

```cedarschema
// Client-domain human with standard, policy-scoped access.
entity User {
  email: String,
  domain: String,
};

// Client-domain human with elevated access (dashboard administration,
// access reviews). Distinct entity type so policy can grant to Admin
// without enumerating individuals.
entity Admin {
  email: String,
  domain: String,
};

// Firm-domain human — the consulting firm's operator, signed in against
// the firm's own Workspace domain. Trusted per-deployment, separately
// from the client domain.
entity Consultant {
  email: String,
  domain: String,
};

// Non-human principal: kura serve's own internal operations,
// provisioning, and (post-handoff) a client's automated agents. v1
// issues no per-agent principal to a consultant's agent — that agent
// acts as the Consultant. This type exists for genuine service accounts.
entity Service {
  name: String,
};
```

**Domain trust, not entity membership, is what separates a `Consultant` from a
`User`.** Both authenticate with Google OAuth; the deployment config decides which
Workspace domain maps to which principal type. An unauthenticated request resolves to
*no principal* and is denied.
