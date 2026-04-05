#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/common.sh"

cd_repo_root
activate_venv
load_local_env_file
use_local_database_defaults
start_db_service
ensure_local_test_database

info "Running the DB-backed pytest suite..."

python -m pytest -q "$@"
