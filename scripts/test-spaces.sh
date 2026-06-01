#!/usr/bin/env bash
#
# Brings up a containerized MinIO that Kura's object-storage integration
# tests run against, and prints the lines to eval to export the
# KURA_TEST_SPACES_* variables the tests read.
#
#   eval "$(scripts/test-spaces.sh)"
#   go test ./internal/storage/...
#
# MinIO speaks the S3 API, so it stands in for DO Spaces locally exactly
# as the disposable Postgres container stands in for DO Managed Postgres.
# It is never DigitalOcean's Spaces — integration tests must run against a
# disposable local instance.
set -euo pipefail

name="kura-test-spaces"
image="minio/minio:latest"
port="${KURA_TEST_SPACES_PORT:-59000}"
access_key="kura-test"
secret_key="kura-test-secret"

docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" -p "${port}:9000" \
  -e MINIO_ROOT_USER="$access_key" \
  -e MINIO_ROOT_PASSWORD="$secret_key" \
  "$image" server /data >/dev/null

# Wait for the S3 endpoint to answer its liveness probe.
for _ in $(seq 1 30); do
  if docker exec "$name" mc ready local >/dev/null 2>&1 ||
    curl -fsS "http://localhost:${port}/minio/health/live" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
if ! curl -fsS "http://localhost:${port}/minio/health/live" >/dev/null 2>&1; then
  echo "test-spaces.sh: MinIO did not become ready in time" >&2
  exit 1
fi

echo "export KURA_TEST_SPACES_ENDPOINT='localhost:${port}'"
echo "export KURA_TEST_SPACES_ACCESS_KEY='${access_key}'"
echo "export KURA_TEST_SPACES_SECRET_KEY='${secret_key}'"
echo "export KURA_TEST_SPACES_REGION='us-east-1'"
