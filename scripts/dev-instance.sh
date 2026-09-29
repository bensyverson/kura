#!/usr/bin/env bash
#
# One-command local Kura for smoking the dashboard end to end.
#
#   scripts/dev-instance.sh
#
# It composes the existing dev runways into a single populated instance:
#
#   1. boots the containerized Postgres (scripts/test-db.sh)
#   2. starts the stub PII detector (kura dev pii-detector)
#   3. starts kura serve, wired to that DB + the dev manifest + a signing
#      secret, fully offline (KURA_IDP=google for sign-in wiring, but
#      KURA_DIRECTORY=none so it never dials a real directory)
#   4. seeds an admin and a user with roles (kura dev seed-users)
#   5. mints + caches an admin token (kura dev token --save)
#   6. ingests the sample records through the real ingestion API
#      (kura ingest)
#   7. shows the same record as admin (SSN visible) and as the user (SSN
#      masked) — the per-principal masking the gate enforces
#   8. opens the dashboard (kura dashboard)
#
# It is idempotent (safe to re-run) and tears down on Ctrl-C: it stops
# serve and the detector and removes the dev DB container. Client
# credentials are cached under an isolated config home so this never
# clobbers your real `kura login`.
#
# Override any setting via the KURA_DEV_* environment variables below.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/.." && pwd)"

# --- configuration (override via env) ---
SERVE_PORT="${KURA_DEV_SERVE_PORT:-8080}"
DASH_PORT="${KURA_DEV_DASHBOARD_PORT:-7878}"
DETECTOR_PORT="${KURA_DEV_DETECTOR_PORT:-8089}"
SIGNING_SECRET="${KURA_DEV_SIGNING_SECRET:-dev-signing-secret-change-me}"
TENANT_ID="${KURA_DEV_TENANT_ID:-00000000-0000-0000-0000-000000000001}"
ENC_KEY="${KURA_DEV_RECORD_ENCRYPTION_KEY:-dev-record-encryption-key}"
FIRM_DOMAIN="${KURA_DEV_FIRM_DOMAIN:-dev.example}"
ADMIN_EMAIL="${KURA_DEV_ADMIN_EMAIL:-admin@dev.example}"
USER_EMAIL="${KURA_DEV_USER_EMAIL:-analyst@dev.example}"

PUBLIC_URL="http://127.0.0.1:${SERVE_PORT}"
DETECTOR_URL="http://127.0.0.1:${DETECTOR_PORT}"

STATE_DIR="${KURA_DEV_STATE_DIR:-$repo_root/.dev-instance}"
CLIENT_HOME="$STATE_DIR/home"
LOG_DIR="$STATE_DIR/logs"
KURA_BIN="$STATE_DIR/kura"
SERVE_PIDFILE="$STATE_DIR/serve.pid"
DETECTOR_PIDFILE="$STATE_DIR/pii-detector.pid"
MANIFEST="$here/dev/manifest.json"
SEED_DIR="$here/dev/seed"

mkdir -p "$STATE_DIR" "$CLIENT_HOME" "$LOG_DIR"

# Client commands cache their token under an isolated config home, so the
# dev instance never overwrites the user's real `kura login` credential.
kura_client() { HOME="$CLIENT_HOME" XDG_CONFIG_HOME="$CLIENT_HOME/.config" "$KURA_BIN" "$@"; }

kill_pidfile() {
  local pf="$1"
  if [[ -f "$pf" ]]; then
    local pid
    pid="$(cat "$pf" 2>/dev/null || true)"
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
    rm -f "$pf"
  fi
}

cleanup() {
  kill_pidfile "$SERVE_PIDFILE"
  kill_pidfile "$DETECTOR_PIDFILE"
  if [[ -z "${KURA_DEV_KEEP_DB:-}" ]]; then
    docker rm -f kura-test-db >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

# Idempotency: clear anything a prior run left holding our ports.
kill_pidfile "$SERVE_PIDFILE"
kill_pidfile "$DETECTOR_PIDFILE"

echo "==> Building kura"
( cd "$repo_root" && go build -o "$KURA_BIN" ./cmd/kura )

echo "==> Starting Postgres (scripts/test-db.sh)"
db_export="$("$here/test-db.sh")"
eval "$db_export" # exports KURA_TEST_DATABASE_URL
export KURA_DATABASE_URL="$KURA_TEST_DATABASE_URL"
# Production splits the runtime (kura_api) and migrator/owner (kura_admin)
# credentials; the local dev DB has one superuser, so both DSNs are the same.
export KURA_ADMIN_DATABASE_URL="$KURA_TEST_DATABASE_URL"
export KURA_DB_TENANT_ID="$TENANT_ID"
export KURA_RECORD_ENCRYPTION_KEY="$ENC_KEY"

echo "==> Starting stub PII detector ($DETECTOR_URL)"
"$KURA_BIN" dev pii-detector --addr "127.0.0.1:${DETECTOR_PORT}" >"$LOG_DIR/pii-detector.log" 2>&1 &
echo $! >"$DETECTOR_PIDFILE"

# --- serve environment ---
# KURA_IDP=google wires the sign-in adapter from string client creds (it
# never dials out at startup). KURA_DIRECTORY=none turns off IdP-mismatch
# detection, so serve stays fully offline — no real Workspace directory.
export KURA_SIGNING_SECRET="$SIGNING_SECRET"
export KURA_IDP="google"
export KURA_DIRECTORY="none"
export KURA_GOOGLE_CLIENT_ID="dev-client-id.apps.googleusercontent.com"
export KURA_GOOGLE_CLIENT_SECRET="dev-client-secret"
export KURA_PUBLIC_URL="$PUBLIC_URL"
export KURA_FIRM_DOMAIN="$FIRM_DOMAIN"
export KURA_PII_DETECTOR_URL="$DETECTOR_URL"
export KURA_MANIFEST_PATH="$MANIFEST"

echo "==> Starting kura serve ($PUBLIC_URL)"
"$KURA_BIN" serve --addr "127.0.0.1:${SERVE_PORT}" >"$LOG_DIR/serve.log" 2>&1 &
serve_pid=$!
echo "$serve_pid" >"$SERVE_PIDFILE"

echo "==> Waiting for serve to become healthy"
ready=""
for _ in $(seq 1 30); do
  if curl -fsS "$PUBLIC_URL/healthz" >/dev/null 2>&1; then ready=1; break; fi
  if ! kill -0 "$serve_pid" 2>/dev/null; then
    echo "serve exited early — see $LOG_DIR/serve.log:" >&2
    tail -n 20 "$LOG_DIR/serve.log" >&2
    exit 1
  fi
  sleep 1
done
if [[ -z "$ready" ]]; then
  echo "serve did not become healthy in time — see $LOG_DIR/serve.log" >&2
  exit 1
fi

echo "==> Seeding users and roles"
"$KURA_BIN" dev seed-users --admin "$ADMIN_EMAIL" --user "$USER_EMAIL"

mint_admin() {
  kura_client dev token --type admin --email "$ADMIN_EMAIL" --tenant "$FIRM_DOMAIN" \
    --save --server "$PUBLIC_URL" >/dev/null
}
mint_user() {
  kura_client dev token --type user --email "$USER_EMAIL" --tenant "$FIRM_DOMAIN" \
    --save --server "$PUBLIC_URL" >/dev/null
}

echo "==> Ingesting sample records"
mint_admin
for f in "$SEED_DIR"/*.json; do
  entity="$(basename "$f" .json)"
  kura_client ingest "$entity" --file "$f" --server "$PUBLIC_URL"
done

echo
echo "==> Reading the same data back through the gate, per principal"
echo "--- as admin ($ADMIN_EMAIL): high-sensitivity (ssn) visible ---"
mint_admin
kura_client query customer --server "$PUBLIC_URL"
echo
echo "--- as user ($USER_EMAIL): high-sensitivity (ssn) masked ---"
mint_user
kura_client query customer --server "$PUBLIC_URL"
echo

# Leave the admin signed in for the dashboard.
mint_admin

echo "==> Opening dashboard (http://127.0.0.1:${DASH_PORT}) — Ctrl-C to tear down"
browser_args=()
[[ -n "${KURA_DEV_NO_BROWSER:-}" ]] && browser_args=(--no-browser)
kura_client dashboard --server "$PUBLIC_URL" --addr "127.0.0.1:${DASH_PORT}" "${browser_args[@]}"
