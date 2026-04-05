#!/usr/bin/env bash

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DEFAULT_LOCAL_DATABASE_URL="postgresql+psycopg://auth:auth@localhost:5432/auth"
DEFAULT_LOCAL_TEST_DATABASE_URL="postgresql+psycopg://auth:auth@localhost:5432/auth_test"


info() {
  echo "==> $*"
}


fail() {
  echo "Error: $*" >&2
  exit 1
}


cd_repo_root() {
  cd "$REPO_ROOT"
}


load_local_env_file() {
  if [ -f "$REPO_ROOT/.env" ]; then
    eval "$(
      REPO_ROOT="$REPO_ROOT" python - <<'PY'
import os
import shlex
from pathlib import Path

from dotenv import dotenv_values

env_path = Path(os.environ["REPO_ROOT"]) / ".env"
for key, value in dotenv_values(env_path).items():
    if value is None:
        continue
    print(f"export {key}={shlex.quote(value)}")
PY
    )"
  fi
}


ensure_venv() {
  if [ ! -x "$REPO_ROOT/.venv/bin/python" ]; then
    fail "Local virtualenv not found at .venv. Create it with: python3 -m venv .venv && . .venv/bin/activate && python -m pip install -e \".[dev]\""
  fi
}


activate_venv() {
  ensure_venv
  # shellcheck disable=SC1091
  source "$REPO_ROOT/.venv/bin/activate"
}


use_local_database_defaults() {
  export DATABASE_URL="${DATABASE_URL:-$DEFAULT_LOCAL_DATABASE_URL}"
  export TEST_DATABASE_URL="${TEST_DATABASE_URL:-$DEFAULT_LOCAL_TEST_DATABASE_URL}"
}


ensure_docker_available() {
  if ! command -v docker >/dev/null 2>&1; then
    fail "Docker is required for the local PostgreSQL helper scripts. Install Docker Desktop or make the docker CLI available first."
  fi

  if ! docker info >/dev/null 2>&1; then
    fail "Docker is installed, but the daemon is not reachable. Start Docker Desktop and try again."
  fi
}


start_db_service() {
  ensure_docker_available
  info "Starting local PostgreSQL container..."
  docker compose up -d db >/dev/null
  wait_for_db_service
}


wait_for_db_service() {
  local attempts=30
  local attempt

  for attempt in $(seq 1 "$attempts"); do
    if docker compose exec -T db pg_isready -U auth -d postgres >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done

  fail "Local PostgreSQL did not become ready in time. Check: docker compose logs db"
}


ensure_local_test_database() {
  if [ "$TEST_DATABASE_URL" != "$DEFAULT_LOCAL_TEST_DATABASE_URL" ]; then
    info "Using custom TEST_DATABASE_URL from the environment."
    return 0
  fi

  if docker compose exec -T db psql -U auth -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='auth_test'" | tr -d '[:space:]' | grep -q '^1$'; then
    return 0
  fi

  info "Creating local auth_test database..."
  if ! docker compose exec -T db psql -U auth -d postgres -c "CREATE DATABASE auth_test;" >/dev/null; then
    fail "Could not create auth_test automatically. If you prefer a different test database, set TEST_DATABASE_URL in .env before running ./scripts/test.sh."
  fi
}
