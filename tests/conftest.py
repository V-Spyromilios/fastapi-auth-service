from __future__ import annotations

import json
import os
from collections.abc import Generator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.services.password_reset_notifier import PasswordResetNotifier


@pytest.fixture(scope="session")
def test_db_url() -> str:
    url = os.getenv("TEST_DATABASE_URL")
    if not url:
        raise RuntimeError("TEST_DATABASE_URL must be set for tests")
    return url


@pytest.fixture(scope="session")
def ed25519_test_keys() -> tuple[str, str]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return private_pem, public_pem

@pytest.fixture(scope="session")
def settings(test_db_url: str, ed25519_test_keys: tuple[str, str]) -> Settings:
    private_pem, public_pem = ed25519_test_keys
    os.environ.update(
        {
            "APP_ENV": "test",
            "DATABASE_URL": test_db_url,
            "JWT_ALG": "EdDSA",
            "JWT_PRIVATE_KEY_KID": "test-kid",
            "JWT_PRIVATE_KEY": private_pem,
            "JWT_PUBLIC_KEYS": json.dumps({"test-kid": public_pem}),
            "JWT_ACCESS_TTL_MINUTES": "15",
            "JWT_REFRESH_TTL_DAYS": "30",
            "REFRESH_TOKEN_PEPPER": "test-pepper",
            "PASSWORD_RESET_TOKEN_TTL_MINUTES": "30",
            "PASSWORD_RESET_TOKEN_PEPPER": "test-password-reset-pepper",
            "LOG_INCLUDE_IP": "false",
            "LOG_INCLUDE_USER_AGENT": "false",
            "LOG_INCLUDE_EMAIL": "false",
        }
    )
    get_settings.cache_clear()
    return get_settings()


@pytest.fixture(scope="session")
def engine(settings: Settings) -> Engine:
    return create_engine(settings.database_url, pool_pre_ping=True)


@pytest.fixture(scope="session", autouse=True)
def apply_migrations(settings: Settings) -> None:
    config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", settings.database_url)
    command.upgrade(config, "head")


@pytest.fixture()
def db_connection(engine: Engine) -> Generator[Connection, None, None]:
    connection = engine.connect()
    transaction = connection.begin()
    try:
        yield connection
    finally:
        transaction.rollback()
        connection.close()


@pytest.fixture()
def db_session(db_connection: Connection) -> Generator[Session, None, None]:
    session = Session(
        bind=db_connection,
        autoflush=False,
        autocommit=False,
        join_transaction_mode="create_savepoint",
    )
    try:
        yield session
    finally:
        session.close()


class RecordingPasswordResetNotifier(PasswordResetNotifier):
    def __init__(self) -> None:
        self.events: list[dict[str, str]] = []

    def send_password_reset(self, *, email: str, reset_token: str) -> None:
        self.events.append({"email": email, "reset_token": reset_token})


@pytest.fixture()
def reset_notifier() -> RecordingPasswordResetNotifier:
    return RecordingPasswordResetNotifier()


@pytest.fixture()
def app(settings: Settings, db_session: Session, reset_notifier: RecordingPasswordResetNotifier):
    from app.api.deps import (
        get_db_dep,
        get_password_reset_notifier_dep,
        get_settings_dep,
        get_token_service_dep,
    )
    from app.main import create_app
    from app.services.token_service import JwtTokenService

    app_instance = create_app()

    def _db_override() -> Generator[Session, None, None]:
        yield db_session

    def _settings_override() -> Settings:
        return settings

    def _token_service_override() -> JwtTokenService:
        return JwtTokenService(settings)

    def _reset_notifier_override() -> RecordingPasswordResetNotifier:
        return reset_notifier

    app_instance.dependency_overrides[get_db_dep] = _db_override
    app_instance.dependency_overrides[get_settings_dep] = _settings_override
    app_instance.dependency_overrides[get_token_service_dep] = _token_service_override
    app_instance.dependency_overrides[get_password_reset_notifier_dep] = _reset_notifier_override

    return app_instance


@pytest.fixture()
def client(app) -> Generator[TestClient, None, None]:
    with TestClient(app) as test_client:
        yield test_client
