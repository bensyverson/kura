---
title: Microsoft Entra directory
weight: 7
---

The **Microsoft Entra directory** is the IdP-side seam Kura reads to
detect **IdP mismatches** — an Entra account that has been blocked or
deleted upstream while still holding Kura roles. It powers
`GET /api/users/mismatches` (and the dashboard's mismatch panel) for
deployments that use the Microsoft IdP for sign-in.

Sign-in (`kura login` → Entra OAuth) does not need the directory. The
directory is needed *after* sign-in, by the admin endpoints, so an
admin or auditor can see *"this person can no longer sign in to
Microsoft, but still holds a role here."*

The directory lookup runs as the **application** (client-credentials
flow), not as a signed-in user — that is what makes it consistent and
audit-independent.

## What you need

- An **Entra tenant** for the firm or client this deployment serves.
- **Admin consent** authority in that tenant — granting an
  application-level Graph permission requires it.
- The same **app registration** you set up for sign-in
  ([Microsoft Entra sign-in](microsoft-sign-in)), or a separate
  registration dedicated to the directory client. A dedicated
  registration is cleaner: revoking the directory's credentials does
  not interrupt sign-in, and vice-versa.

## Grant the minimum permission

Kura needs to read **one bit** of state per user (`accountEnabled` —
true or false). Grant only the **application** permission
`User.Read.All`; no other Graph permission is needed, and adding more
is a footgun.

1. Open the app registration in the [Entra admin center][admin].
2. **API permissions → Add a permission → Microsoft Graph →
   Application permissions**. (Application, *not* Delegated — the
   directory client runs as the app, not as a signed-in user.)
3. Search for and add **`User.Read.All`**.
4. **Grant admin consent for <tenant>**. Application permissions
   always require admin consent; without it, every Graph call returns
   `403 Insufficient privileges`.
5. Do **not** add Directory.Read.All, User.ReadWrite.All, or any other
   Graph permission. The read-only `User.Read.All` is the minimum.

## Create a client secret

If you are reusing the sign-in app registration, the existing client
secret works for the directory as well. Otherwise, create one:

1. **Certificates & secrets → Client secrets → New client secret**.
2. Description (for example `kura-directory`) and an expiry. The
   shortest expiry you can rotate before is best practice — 6 or 12
   months is typical.
3. Copy the **Value** (not the Secret ID) immediately; Entra will not
   show it again. This is `KURA_MICROSOFT_DIRECTORY_CLIENT_SECRET`.

## Configure `kura serve`

| Variable                                  | Value                                                    |
| ----------------------------------------- | -------------------------------------------------------- |
| `KURA_MICROSOFT_DIRECTORY_TENANT_ID`      | Directory (tenant) ID — the tenant whose users to query  |
| `KURA_MICROSOFT_DIRECTORY_CLIENT_ID`      | Application (client) ID of the app registration          |
| `KURA_MICROSOFT_DIRECTORY_CLIENT_SECRET`  | Client secret **Value** from the registration            |

The directory's `KURA_MICROSOFT_DIRECTORY_TENANT_ID` does **not** accept
`common`; unlike sign-in, a directory query is always against a
specific tenant.

## Verify

With the directory wired, `GET /api/users/mismatches` returns the real
upstream status of every user holding a Kura role. A blocked or deleted
Entra account that still holds a role shows up here; an active account
does not.

If a lookup fails (network, revoked consent, expired secret), the
mismatch endpoint surfaces the Graph error rather than silently
treating users as absent.

[admin]: https://entra.microsoft.com/
