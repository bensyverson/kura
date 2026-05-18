---
title: Microsoft Entra sign-in
weight: 3
---

Kura accepts sign-in from **Microsoft Entra (Azure AD)** as well as Google
Workspace. The Microsoft IdP is one implementation of the same
`IdentityProvider` seam the Google IdP uses — the trust model, token
model, and audit log are identical. Only the IdP-side setup changes.

This page walks through the Entra-side registration a deployment needs
before `kura serve` can broker sign-in.

## What you need

- An **Entra tenant**. A firm using Microsoft 365 already has one. If
  you do not have a tenant to develop against, the free
  [Microsoft 365 Developer Program][m365dev] grants a renewable
  developer tenant.
- **Admin or Application Developer access** to that tenant — registering
  an app requires it.
- The **public URL** of the Kura deployment (the URL `kura serve`
  answers on). The `/oauth/callback` path under that URL is the
  redirect URI you will register below.

## Register the app

1. Open the [Microsoft Entra admin center][admin] (or the Azure portal)
   and switch to the tenant you want sign-in to be served from.
2. Navigate to **Identity → Applications → App registrations** and
   choose **New registration**.
3. **Name** — anything recognizable, for example `Kura — <client
   engagement name>`. The name is visible only to admins.
4. **Supported account types** — pick one:
   - **Accounts in this organizational directory only** (single tenant) —
     restricts sign-in to one Entra tenant. Recommended for a typical
     client deployment.
   - **Accounts in any organizational directory** (multi-tenant) — use
     only if the deployment must accept sign-in from more than one
     Entra tenant; you will configure the trust list in Kura to name
     each accepted tenant ID.
5. **Redirect URI** — choose **Web** and enter
   `https://<your-kura-public-url>/oauth/callback`. The URI must match
   the `KURA_PUBLIC_URL` the server is configured with, exactly.
6. Click **Register**.

## Capture the configuration values

On the new app's **Overview** page, copy two values:

- **Application (client) ID** — this becomes `KURA_MICROSOFT_CLIENT_ID`.
- **Directory (tenant) ID** — this becomes `KURA_MICROSOFT_TENANT_ID`
  for a single-tenant deployment. For multi-tenant, use the literal
  string `common` instead of the GUID.

Then create a client secret:

1. **Certificates & secrets → Client secrets → New client secret**.
2. Give it a description (for example `kura-serve`) and an expiry. Pick
   the shortest expiry you can rotate before — 6 or 12 months is
   typical. Entra will not let you read the secret value again after
   you leave the page.
3. Copy the **Value** (not the Secret ID). This becomes
   `KURA_MICROSOFT_CLIENT_SECRET`.

## Grant the minimum permissions

Kura needs the user's identity, nothing else.

1. **API permissions → Add a permission → Microsoft Graph → Delegated
   permissions**.
2. Add **`User.Read`**. This is the minimum permission Microsoft
   requires for a sign-in app to receive a user's basic profile (and is
   the default for new app registrations — confirm it is listed).
3. Do **not** add Mail, Files, Calendar, or any other Graph permission
   unless a specific feature in your deployment needs it. Kura itself
   never calls Graph for data; it consumes only the `id_token`.
4. Admin consent — if your tenant requires admin consent for delegated
   permissions, click **Grant admin consent for <tenant>**. `User.Read`
   typically does not require it.

## Configure `kura serve`

With those four values in hand, set the corresponding environment
variables when running `kura serve`:

| Variable                          | Value                                              |
| --------------------------------- | -------------------------------------------------- |
| `KURA_IDP`                        | `microsoft`                                        |
| `KURA_MICROSOFT_CLIENT_ID`        | Application (client) ID                            |
| `KURA_MICROSOFT_CLIENT_SECRET`    | Client secret **Value** from the registration step |
| `KURA_MICROSOFT_TENANT_ID`        | Directory (tenant) ID, or `common` for multi-tenant |
| `KURA_PUBLIC_URL`                 | The deployment's public URL                        |

The Kura-side tenant-trust configuration
(`KURA_FIRM_TENANT`, `KURA_CLIENT_TENANTS`, `KURA_ADMIN_EMAILS`) works
the same as for the Google IdP — for Microsoft, the **tenant key is
the Entra Directory (tenant) ID**, not a domain. Put each accepted
tenant ID in the trust list.

> `KURA_IDP` accepts `google` (default) and `oidc` today; selection of
> the Microsoft IdP family from `kura serve` lands with the Phase E
> config-plumbing task. Until then, the Entra-side registration above
> stands but `kura serve` will not yet wire `microsoft` from
> `KURA_IDP`. The registration is unchanged when the selector lands.

## Verify

Once the server is running, `kura login` opens the Entra consent screen
in your browser. After consent, the browser is redirected to
`/oauth/callback` on your Kura public URL, the server verifies the
id_token, and the CLI receives a short-lived Kura token. The token is
the identity; from that point on, the session behaves exactly like a
Google-authenticated session.

If sign-in fails, the audit log records a `denied` authentication event
with the failure reason — invalid signature, untrusted tenant, missing
`tid` claim. The browser shows a generic failure; the audit log has
the diagnostic.

[admin]: https://entra.microsoft.com/
[m365dev]: https://developer.microsoft.com/microsoft-365/dev-program
