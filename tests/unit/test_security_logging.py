from __future__ import annotations

import uuid

from starlette.requests import Request

from app.core.config import Settings
from app.core.logging import build_request_log_context, build_security_log_fields


def _settings(**overrides) -> Settings:
    values = {
        "database_url": "postgresql+psycopg://auth:auth@localhost:5432/auth",
        "app_trust_proxy": False,
        "log_include_ip": False,
        "log_include_user_agent": False,
        "log_include_email": False,
    }
    values.update(overrides)
    return Settings.model_construct(**values)


def test_build_security_log_fields_respects_email_flag() -> None:
    user_id = uuid.uuid4()
    family_id = uuid.uuid4()
    settings = _settings(log_include_email=False)

    fields = build_security_log_fields(
        settings,
        user_id=user_id,
        email="user@example.com",
        outcome="failure",
        reason="invalid_credentials",
        family_id=family_id,
    )

    assert fields == {
        "user_id": str(user_id),
        "outcome": "failure",
        "reason": "invalid_credentials",
        "family_id": str(family_id),
    }


def test_build_request_log_context_respects_metadata_flags() -> None:
    settings = _settings(
        app_trust_proxy=True,
        log_include_ip=True,
        log_include_user_agent=True,
    )
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/auth/login",
            "headers": [
                (b"x-forwarded-for", b"203.0.113.7, 127.0.0.1"),
                (b"user-agent", b"pytest-agent"),
            ],
            "client": ("127.0.0.1", 1234),
        }
    )
    request.state.request_id = "req-123"

    context = build_request_log_context(request, settings)

    assert context == {
        "request_id": "req-123",
        "client_ip": "203.0.113.7",
        "user_agent": "pytest-agent",
    }
