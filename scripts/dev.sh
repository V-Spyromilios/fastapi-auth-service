#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -d ".venv" ]; then
  echo "Error: .venv not found. Create it first." >&2
  exit 1
fi

source .venv/bin/activate

export DATABASE_URL='postgresql+psycopg://auth:auth@localhost:5432/auth'

docker compose up -d db

uvicorn app.main:app --reload
