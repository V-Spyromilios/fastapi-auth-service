#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/common.sh"

cd_repo_root
activate_venv
load_local_env_file
use_local_database_defaults

if [ ! -f ".env" ]; then
  fail "Missing .env. Copy .env.example to .env and fill in the local JWT settings before starting the app."
fi

start_db_service

info "Starting FastAPI dev server on http://127.0.0.1:${APP_PORT:-8000}"
info "Liveness: http://127.0.0.1:${APP_PORT:-8000}/health"
info "Readiness: http://127.0.0.1:${APP_PORT:-8000}/ready"

uvicorn app.main:app --reload --host "${APP_HOST:-0.0.0.0}" --port "${APP_PORT:-8000}"
