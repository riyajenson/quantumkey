#!/usr/bin/env bash
# Runs the relying-party suite and the Alembic check against a throwaway PostgreSQL 17
# container on loopback. Needs Docker and an activated venv with the test extras.
set -euo pipefail

IMAGE='postgres:17@sha256:b8faeff7712663c2773a190181e1246e37e364b887611c04658c28b44e2408fe'
PASSWORD=$(python -c "import secrets; print(secrets.token_hex(12))")
CID=$(docker run --rm -d -e POSTGRES_USER=qk_test_user -e POSTGRES_PASSWORD="$PASSWORD" \
  -e POSTGRES_DB=qk_test_server -p 127.0.0.1::5432 "$IMAGE")
trap 'docker stop "$CID" >/dev/null' EXIT

for _ in $(seq 1 60); do
  docker exec "$CID" pg_isready -U qk_test_user -d qk_test_server >/dev/null 2>&1 && break
  sleep 1
done
sleep 2
PORT=$(docker port "$CID" 5432/tcp | head -1 | sed 's/.*://')
export QK_TEST_DATABASE_URL="postgresql+psycopg://qk_test_user:${PASSWORD}@127.0.0.1:${PORT}/qk_test_server"
python -m pytest tests/server -q
