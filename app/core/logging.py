from __future__ import annotations

import logging
from enum import Enum
from typing import Any
from uuid import UUID

import structlog
from fastapi import Request

from app.core.config import Settings
from app.core.rate_limit import get_client_ip


def get_logger(name: str):
    return structlog.get_logger(name)


def configure_logging(settings: Settings) -> None:
    logging.basicConfig(level=settings.app_log_level.value)

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelName(settings.app_log_level.value)
        ),
        cache_logger_on_first_use=True,
    )


def build_request_log_context(request: Request, settings: Settings) -> dict[str, str]:
    context: dict[str, str] = {}
    request_id = getattr(request.state, "request_id", None)
    if request_id:
        context["request_id"] = request_id

    if settings.log_include_ip:
        context["client_ip"] = get_client_ip(request, trust_proxy=settings.app_trust_proxy)

    if settings.log_include_user_agent:
        user_agent = request.headers.get("User-Agent")
        if user_agent:
            context["user_agent"] = user_agent

    return context


def bind_request_log_context(request: Request, settings: Settings) -> None:
    structlog.contextvars.clear_contextvars()
    context = build_request_log_context(request, settings)
    if context:
        structlog.contextvars.bind_contextvars(**context)


def clear_request_log_context() -> None:
    structlog.contextvars.clear_contextvars()


def build_security_log_fields(
    settings: Settings,
    *,
    user_id: UUID | str | None = None,
    email: str | None = None,
    outcome: str | None = None,
    reason: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    if user_id is not None:
        fields["user_id"] = str(user_id)
    if settings.log_include_email and email:
        fields["email"] = email.strip()
    if outcome is not None:
        fields["outcome"] = outcome
    if reason is not None:
        fields["reason"] = reason

    for key, value in extra.items():
        if value is None:
            continue
        if isinstance(value, UUID):
            fields[key] = str(value)
        elif isinstance(value, Enum):
            fields[key] = value.value
        else:
            fields[key] = value

    return fields


def log_security_event(
    settings: Settings,
    event: str,
    *,
    level: str = "info",
    user_id: UUID | str | None = None,
    email: str | None = None,
    outcome: str | None = None,
    reason: str | None = None,
    **extra: Any,
) -> None:
    logger = get_logger("app.security")
    log_method = getattr(logger, level)
    log_method(
        event,
        **build_security_log_fields(
            settings,
            user_id=user_id,
            email=email,
            outcome=outcome,
            reason=reason,
            **extra,
        ),
    )
