#!/usr/bin/env bash
#
# Smoke-tests the end-to-end `kura login` OAuth flow against a real Google
# Workspace domain — the manual check behind build-plan criterion Qu7
# ("the OAuth flow completes end-to-end against a real Google Workspace
# test domain").
#
# It cannot be fully automated: a human completes the Google sign-in in a
# browser. What it automates is the setup, the teardown, and the
# verification that the token the server minted actually resolves.
#
# The whole test runs locally — Google permits http://127.0.0.1 redirect
# URIs, so no TLS, no Caddy, and no public host are needed.
#
# PREREQUISITES
#
#   A Google OAuth 2.0 client of type "Web application", with
#
#       http://127.0.0.1:8080/oauth/callback
#
#   registered as an Authorized redirect URI, and these exported:
#
#       KURA_GOOGLE_CLIENT_ID      the OAuth client ID
#       KURA_GOOGLE_CLIENT_SECRET  the OAuth client secret
#       KURA_FIRM_DOMAIN           the Workspace domain you will sign in
#                                  with — a sign-in here lands as a
#                                  Consultant
#
#   Optional, to exercise the client-domain branches instead:
#
#       KURA_CLIENT_DOMAINS        comma-separated client Workspace domains
#       KURA_ADMIN_EMAILS          comma-separated admin emails
#
# USAGE
#
#   export KURA_GOOGLE_CLIENT_ID=...
#   export KURA_GOOGLE_CLIENT_SECRET=...
#   export KURA_FIRM_DOMAIN=yourfirm.com
#   scripts/oauth-smoke.sh
#
set -euo pipefail

ADDR="127.0.0.1:8080"
PUBLIC_URL="http://${ADDR}"

# --- check prerequisites ----------------------------------------------
missing=0
for v in KURA_GOOGLE_CLIENT_ID KURA_GOOGLE_CLIENT_SECRET KURA_FIRM_DOMAIN; do
	if [[ -z "${!v:-}" ]]; then
		echo "missing required env var: $v" >&2
		missing=1
	fi
done
if [[ $missing -ne 0 ]]; then
	echo >&2
	echo "see the header of this script for the full setup." >&2
	exit 1
fi

# The signing secret only needs to be stable for the life of this run.
export KURA_SIGNING_SECRET="${KURA_SIGNING_SECRET:-$(head -c 32 /dev/urandom | base64)}"
export KURA_PUBLIC_URL="$PUBLIC_URL"

# --- build ------------------------------------------------------------
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
workdir="$(mktemp -d)"
bin="${workdir}/kura"
trap 'rm -rf "$workdir"' EXIT
echo "building kura..."
go build -o "$bin" ./cmd/kura

# --- start the server -------------------------------------------------
echo "starting kura serve on ${ADDR}..."
"$bin" serve --addr "$ADDR" &
serve_pid=$!
trap 'kill "$serve_pid" 2>/dev/null || true; rm -rf "$workdir"' EXIT

ready=0
for _ in $(seq 1 50); do
	if curl -fsS "${PUBLIC_URL}/healthz" >/dev/null 2>&1; then
		ready=1
		break
	fi
	sleep 0.1
done
if [[ $ready -ne 1 ]]; then
	echo "FAIL: kura serve did not become healthy" >&2
	exit 1
fi

# --- run the interactive login ----------------------------------------
echo
echo "-----------------------------------------------------------------"
echo "running 'kura login' — your browser will open."
echo "sign in with a ${KURA_FIRM_DOMAIN} Google Workspace account."
echo "-----------------------------------------------------------------"
echo
if ! "$bin" login --server "$PUBLIC_URL"; then
	echo >&2
	echo "FAIL: kura login did not complete" >&2
	exit 1
fi

# --- locate the cached credential -------------------------------------
cred=""
for dir in "${HOME}/Library/Application Support/kura" "${HOME}/.config/kura"; do
	if [[ -f "${dir}/credentials.json" ]]; then
		cred="${dir}/credentials.json"
		break
	fi
done
if [[ -z "$cred" ]]; then
	echo "FAIL: kura login reported success but cached no credential" >&2
	exit 1
fi
echo
echo "cached credential: $cred"

token="$(sed -n 's/.*"token":"\([^"]*\)".*/\1/p' "$cred")"
if [[ -z "$token" ]]; then
	echo "FAIL: cached credential carries no token" >&2
	exit 1
fi

# Decode the token payload (body of body.sig, raw-base64url JSON) just to
# show which principal the firm domain resolved to. Best-effort: the
# authoritative check is the request below.
body="${token%%.*}"
pad=$(( (4 - ${#body} % 4) % 4 ))
printf -v padded '%s%*s' "$body" "$pad" ""
claims="$(printf '%s' "${padded// /=}" | tr '_-' '/+' | base64 -d 2>/dev/null || true)"
if [[ -n "$claims" ]]; then
	echo "token claims: $claims"
fi

# --- verify the token resolves on a real request ----------------------
# An /api request with the minted token must pass requireAuth. The
# skeleton has no data handlers yet, so a resolved token yields 404 (not
# found) while a rejected one yields 401 (unauthorized) — so 404 is the
# pass signal here.
status="$(curl -s -o /dev/null -w '%{http_code}' \
	-H "Authorization: Bearer ${token}" \
	"${PUBLIC_URL}/api/_oauth_smoke_check")"
echo "GET /api/_oauth_smoke_check with the minted token -> ${status}"

echo
if [[ "$status" == "401" ]]; then
	echo "FAIL: the minted token was rejected by requireAuth"
	exit 1
elif [[ "$status" == "404" ]]; then
	echo "PASS: end-to-end OAuth flow works — Google sign-in minted a token"
	echo "      that resolves to a principal on a real request."
	echo
	echo "criterion Qu7 can be checked off."
else
	echo "INCONCLUSIVE: unexpected status ${status} (expected 404)."
	exit 1
fi
