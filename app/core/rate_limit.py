from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from math import ceil
from threading import Lock
from time import monotonic
from typing import Callable, Protocol

from fastapi import Request

from app.core.config import Settings
from app.core.errors import RateLimitExceededError


class RateLimitScope(StrEnum):
    LOGIN = "login"
    PASSWORD_RESET = "password_reset"


@dataclass(frozen=True)
class RateLimitRule:
    window_seconds: int
    max_requests: int


@dataclass
class _FixedWindowState:
    window_started_at: float
    count: int


class RateLimiter(Protocol):
    def check(self, scope: RateLimitScope, key: str) -> None:
        """Raise an exception if rate limit is exceeded."""
        raise NotImplementedError


class NoopRateLimiter:
    def check(self, scope: RateLimitScope, key: str) -> None:
        del scope, key
        return None


class InMemoryFixedWindowRateLimiter:
    def __init__(
        self,
        rules: dict[RateLimitScope, RateLimitRule],
        *,
        now_fn: Callable[[], float] = monotonic,
    ) -> None:
        self._rules = rules
        self._now_fn = now_fn
        self._states: dict[tuple[RateLimitScope, str], _FixedWindowState] = {}
        self._lock = Lock()

    def check(self, scope: RateLimitScope, key: str) -> None:
        rule = self._rules.get(scope)
        if rule is None:
            return None

        now = self._now_fn()
        state_key = (scope, key)
        with self._lock:
            state = self._states.get(state_key)
            if state is None or now - state.window_started_at >= rule.window_seconds:
                self._states[state_key] = _FixedWindowState(window_started_at=now, count=1)
                return None

            if state.count >= rule.max_requests:
                retry_after_seconds = max(
                    1,
                    ceil(rule.window_seconds - (now - state.window_started_at)),
                )
                raise RateLimitExceededError(retry_after_seconds=retry_after_seconds)

            state.count += 1
            return None


def build_rate_limiter(settings: Settings) -> RateLimiter:
    if not settings.rate_limit_enabled:
        return NoopRateLimiter()

    rules = {
        RateLimitScope.LOGIN: RateLimitRule(
            window_seconds=settings.login_rate_limit_window_seconds,
            max_requests=settings.login_rate_limit_max_requests,
        ),
        RateLimitScope.PASSWORD_RESET: RateLimitRule(
            window_seconds=settings.password_reset_rate_limit_window_seconds,
            max_requests=settings.password_reset_rate_limit_max_requests,
        ),
    }
    return InMemoryFixedWindowRateLimiter(rules)


def get_client_ip(request: Request, *, trust_proxy: bool) -> str:
    if trust_proxy:
        forwarded_for = request.headers.get("X-Forwarded-For", "")
        forwarded_ip = forwarded_for.split(",")[0].strip()
        if forwarded_ip:
            return forwarded_ip

    if request.client and request.client.host:
        return request.client.host

    return "unknown"
