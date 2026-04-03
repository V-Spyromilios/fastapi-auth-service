# FastAPI Auth Service

A production-minded FastAPI authentication service built to learn backend engineering fundamentals with Python, PostgreSQL, Docker, Alembic, and automated tests.

## Features

- User registration
- Login with JWT access and refresh tokens
- Refresh token rotation and replay detection
- Logout
- Forgot-password and reset-password flow
- Access token invalidation after password reset
- PostgreSQL with Alembic migrations
- Dockerized local database setup
- Unit and integration tests

## Tech Stack

- FastAPI
- SQLAlchemy
- PostgreSQL
- Alembic
- PyJWT
- Passlib / Argon2id
- Pytest
- Docker Compose

## Quick Start

1. Copy `.env.example` to `.env` and fill in local values.
2. Create a local virtual environment and install dependencies with `python3 -m venv .venv && . .venv/bin/activate && python -m pip install -e ".[dev]"`.
3. Start the database with `docker compose up -d db`.
4. Run migrations with `DATABASE_URL=postgresql+psycopg://auth:auth@localhost:5432/auth ./scripts/init_db.sh`.
5. Start the app with `./scripts/dev.sh`.
6. Create a local test database once with `docker compose exec db psql -U auth -d postgres -c "CREATE DATABASE auth_test;"`.
7. Run tests with `./scripts/test.sh`.

The helper scripts in `scripts/` assume a local `.venv` and local PostgreSQL running via Docker Compose.

## API

Main routes:

- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`
- `POST /api/v1/auth/logout`
- `POST /api/v1/auth/forgot-password`
- `POST /api/v1/auth/reset-password`
- `GET /api/v1/users/me`
- `GET /health`
- `GET /docs`

## Project Structure

- `app/` application code
- `tests/` unit, integration, and migration tests
- `scripts/` helper scripts for local development

## CI

GitHub Actions runs the test suite automatically on every push and pull request using a PostgreSQL service container in CI.

The CI workflow runs `ruff check .` and `python -m pytest -q`.

Local development still uses `.env`. Basic CI for this repository does not require GitHub Secrets, because the tests generate their own JWT test keys and use safe CI-only environment values. GitHub Secrets are better reserved for future deployment or production-style workflows.

You can view CI results in the repository's `Actions` tab and on each pull request check summary.

## Why I built this

I built this project to move from mobile development toward backend engineering and to learn real-world concerns like authentication, token lifecycle management, password reset flows, migrations, testing, and local containerized development.
