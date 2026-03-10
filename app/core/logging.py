from __future__ import annotations

import logging

import structlog

from app.core.config import Settings


def configure_logging(settings: Settings) -> None:
    logging.basicConfig(level=settings.app_log_level.value)

    structlog.configure(
        processors=[
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
