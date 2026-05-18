---
title: Google Workspace directory
weight: 6
---

The **Google Workspace directory** is the IdP-side seam Kura reads to
detect **IdP mismatches** — a Workspace account that is suspended or
absent upstream while still holding Kura roles. The directory lookup is
what makes `GET /api/users/mismatches` (and the dashboard's mismatch
panel) work against live Workspace state instead of an in-memory
placeholder.

Sign-in (`kura login`) does not need the directory at all — it only
verifies an `id_token`. The directory is needed *after* sign-in, by the
admin endpoints, so an admin or auditor can see *"this person no longer
exists in Google, but still holds a role here"*.

## What you need

- A **Google Workspace tenant** for the firm. The same one users sign in
  from.
- **Super-admin or delegated-admin access** to the Workspace admin
  console — granting domain-wide delegation requires it.
- A **Google Cloud project** to host a service account. Any project will
  do; the service account is what Kura authenticates as. The project
  must have the **Admin SDK API** enabled.

## Create the service account

1. Open the [Google Cloud Console][gcp] and select (or create) a
   project to host the service account.
2. **APIs & Services → Library → Admin SDK API → Enable**.
3. **IAM & Admin → Service Accounts → Create service account**.
4. **Name** — anything recognizable, for example `kura-directory`. No
   GCP roles are needed; this service account never touches GCP
   resources.
5. After creating it, open the service account and switch to **Keys →
   Add Key → Create new key → JSON**. Download the file. This is the
   credentials file Kura reads via `KURA_GOOGLE_DIRECTORY_CREDENTIALS`.

Keep the JSON key file out of version control. Treat it like any other
secret.

## Grant the minimum scope — domain-wide delegation

Kura needs to read **one bit** of state per user (suspended or not).
Grant only the **read-only directory user** scope; no other Admin SDK
scope is needed, and adding more is a footgun.

1. On the service account's detail page, copy the **Client ID** (the
   numeric ID, not the email).
2. Open the [Workspace admin console][ws-admin] as a super admin.
3. **Security → Access and data control → API controls → Domain-wide
   delegation → Add new**.
4. **Client ID** — paste the service account's numeric Client ID.
5. **OAuth scopes** — enter exactly:

   ```
   https://www.googleapis.com/auth/admin.directory.user.readonly
   ```

   That is the only scope Kura's directory lookup uses. Granting a
   broader scope (for example `admin.directory.user` without
   `.readonly`) would let an exfiltrated key *mutate* directory state;
   the read-only scope cannot.
6. **Authorize**.

## Pick an admin to impersonate

The Admin SDK refuses anonymous calls — every request runs *as* a
Workspace admin. The service account uses **domain-wide delegation** to
impersonate one. Pick an existing Workspace admin (most deployments
designate a dedicated, low-blast-radius admin for service-account
impersonation) and put their email in `KURA_GOOGLE_DIRECTORY_SUBJECT`.
The Admin SDK rejects non-admin subjects, so this email must hold an
admin role in the Workspace.

## Configure `kura serve`

Set these environment variables alongside the Google IdP sign-in
variables:

| Variable                              | Value                                                                |
| ------------------------------------- | -------------------------------------------------------------------- |
| `KURA_GOOGLE_DIRECTORY_CREDENTIALS`   | Path to the downloaded service-account JSON key file                 |
| `KURA_GOOGLE_DIRECTORY_SUBJECT`       | Workspace admin email the service account impersonates              |

The directory is independent of sign-in: a deployment can run with the
Google IdP and no directory (mismatch detection then reports no
mismatches), or wire the directory in later without touching sign-in.

## Verify

With the directory wired, `GET /api/users/mismatches` returns the real
upstream status of every user holding a Kura role. A suspended or
deleted Workspace account that still holds a role shows up here; an
active account does not.

If the lookup fails (network failure, revoked delegation, wrong
subject), the mismatch endpoint surfaces the error rather than silently
treating users as absent. The Admin SDK's own error message is in the
response so the admin can see what to fix.

[gcp]: https://console.cloud.google.com/
[ws-admin]: https://admin.google.com/
