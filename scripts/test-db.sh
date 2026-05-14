#!/usr/bin/env bash
#
# Brings up the containerized Postgres that Kura's integration tests run
# against, and prints the line to eval to export KURA_TEST_DATABASE_URL.
#
#   eval "$(scripts/test-db.sh)"
#   go test ./...
#
# Or, in one step:  make test-integration
#
# The container bundles pgaudit and a self-signed TLS certificate (see
# scripts/Dockerfile.testdb). It is never DigitalOcean's Postgres — DO
# Managed Postgres is just hosted Postgres, and integration tests must run
# against a disposable local instance.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

name="kura-test-db"
image="kura-test-db:latest"
port="${KURA_TEST_DB_PORT:-55432}"
password="kura-test"

docker build --quiet -t "$image" -f "$here/Dockerfile.testdb" "$here" >/dev/null

docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" -p "${port}:5432" \
  -e POSTGRES_PASSWORD="$password" \
  "$image" \
  -c ssl=on \
  -c ssl_cert_file=/etc/postgres-certs/server.crt \
  -c ssl_key_file=/etc/postgres-certs/server.key \
  -c shared_preload_libraries=pgaudit >/dev/null

# Wait for the server to accept connections.
for _ in $(seq 1 30); do
  if docker exec "$name" pg_isready -U postgres >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
if ! docker exec "$name" pg_isready -U postgres >/dev/null 2>&1; then
  echo "test-db.sh: Postgres did not become ready in time" >&2
  exit 1
fi

echo "export KURA_TEST_DATABASE_URL='postgres://postgres:${password}@localhost:${port}/postgres?sslmode=require'"
