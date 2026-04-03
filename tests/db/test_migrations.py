from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect


def test_alembic_upgrade_head_creates_key_tables(settings, engine) -> None:
    config = Config(str(Path(__file__).resolve().parents[2] / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", settings.database_url)

    command.upgrade(config, "head")

    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    assert "users" in tables
    assert "refresh_tokens" in tables
    assert "password_reset_tokens" in tables

    user_columns = {column["name"] for column in inspector.get_columns("users")}
    assert "password_changed_at" in user_columns
