#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/common.sh"

cd_repo_root
activate_venv
load_local_env_file
use_local_database_defaults
start_db_service

info "Running Alembic migrations..."
alembic upgrade head
info "Database schema is up to date."
