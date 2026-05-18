#!/usr/bin/env bash
#
# Smoke-tests the end-to-end `kura login` flow against a generic OIDC
# IdP — Zitadel, Keycloak, Okta, Auth0, or any other provider that
# implements OIDC Discovery and JWKS.
#
# It is the OIDC analogue of oauth-smoke.sh (which is Google-specific):
# automates the setup and teardown around an interactive sign-in, then
# verifies the token the server minted actually resolves on a real API
# request.
#
# PREREQUISITES
#
#   An OIDC client registered with the IdP, with
#
#       http://127.0.0.1:8080/oauth/callback
#
#   as a redirect URI, and these exported:
#
#       KURA_OIDC_ISSUER_URL    the IdP's issuer URL — discovery happens
#                               at <URL>/.well-known/openid-configuration
#       KURA_OIDC_CLIENT_ID     the OIDC client ID
#       KURA_OIDC_CLIENT_SECRET the OIDC client secret
#       KURA_FIRM_DOMAIN        the tenant string Kura should treat as
#                               the firm. For generic OIDC, this is the
#                               issuer URL — Kura uses issuer-as-tenant
#                               for vendors without a tenant claim.
#
#   For Keycloak's dev stack, that means:
#
#       export KURA_OIDC_ISSUER_URL=http://localhost:8085/realms/kura
#       export KURA_OIDC_CLIENT_ID=kura
#       export KURA_OIDC_CLIENT_SECRET=kura-dev-secret
#       export KURA_FIRM_DOMAIN=http://localhost:8085/realms/kura
#
#   See scripts/oidc-dev/ for the docker-compose stacks that boot a real
#   Keycloak or Zitadel locally.
#
# USAGE
#
#   scripts/oidc-smoke.sh
#
set -euo pipefail

ADDR="127.0.0.1:8080"
PUBLIC_URL="http://${ADDR}"

# --- check prerequisites ----------------------------------------------
missing=0
for v in KURA_OIDC_ISSUER_URL KURA_OIDC_CLIENT_ID KURA_OIDC_CLIENT_SECRET KURA_FIRM_DOMAIN; do
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

# Required by kura serve regardless of IdP.
export KURA_IDP=oidc
export KURA_SIGNING_SECRET="${KURA_SIGNING_SECRET:-$(head -c 32 /dev/urandom | base64)}"
export KURA_PUBLIC_URL="$PUBLIC_URL"
export KURA_PII_DETECTOR_URL="${KURA_PII_DETECTOR_URL:-http://127.0.0.1:9100/detect}"

# --- build ------------------------------------------------------------
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
workdir="$(mktemp -d)"
bin="${workdir}/kura"
trap 'rm -rf "$workdir"' EXIT
echo "building kura..."
go build -o "$bin" ./cmd/kura

# --- start the server -------------------------------------------------
echo "starting kura serve on ${ADDR} against ${KURA_OIDC_ISSUER_URL}..."
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
echo "sign in at ${KURA_OIDC_ISSUER_URL}."
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

# Decode the token payload (body of body.sig, raw-base64url JSON) to
# show which principal the issuer resolved to.
body="${token%%.*}"
pad=$(( (4 - ${#body} % 4) % 4 ))
printf -v padded '%s%*s' "$body" "$pad" ""
claims="$(printf '%s' "${padded// /=}" | tr '_-' '/+' | base64 -d 2>/dev/null || true)"
if [[ -n "$claims" ]]; then
	echo "token claims: $claims"
fi

# --- verify the token resolves on a real request ----------------------
# Same protocol as oauth-smoke.sh: a resolved token yields 404 (no
# data routes registered against an empty manifest), a rejected one
# yields 401. So 404 is the pass signal.
status="$(curl -s -o /dev/null -w '%{http_code}' \
	-H "Authorization: Bearer ${token}" \
	"${PUBLIC_URL}/api/_oidc_smoke_check")"
echo "GET /api/_oidc_smoke_check with the minted token -> ${status}"

echo
if [[ "$status" == "401" ]]; then
	echo "FAIL: the minted token was rejected by requireAuth"
	exit 1
elif [[ "$status" == "404" ]]; then
	echo "PASS: end-to-end OIDC sign-in works — ${KURA_OIDC_ISSUER_URL} minted"
	echo "      a token that resolves to a principal on a real request."
else
	echo "UNEXPECTED status ${status}"
	exit 1
fi
