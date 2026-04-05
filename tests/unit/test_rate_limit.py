from __future__ import annotations

import pytest

from app.core.errors import RateLimitExceededError
from app.core.rate_limit import InMemoryFixedWindowRateLimiter, RateLimitRule, RateLimitScope


class FakeClock:
    def __init__(self, start: float = 0.0) -> None:
        self._now = start

    def now(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


def test_in_memory_rate_limiter_resets_after_the_window() -> None:
    clock = FakeClock()
    limiter = InMemoryFixedWindowRateLimiter(
        {
            RateLimitScope.LOGIN: RateLimitRule(window_seconds=10, max_requests=1),
        },
        now_fn=clock.now,
    )

    limiter.check(RateLimitScope.LOGIN, "127.0.0.1")

    with pytest.raises(RateLimitExceededError):
        limiter.check(RateLimitScope.LOGIN, "127.0.0.1")

    clock.advance(10)
    limiter.check(RateLimitScope.LOGIN, "127.0.0.1")


def test_in_memory_rate_limiter_sets_retry_after() -> None:
    clock = FakeClock()
    limiter = InMemoryFixedWindowRateLimiter(
        {
            RateLimitScope.PASSWORD_RESET: RateLimitRule(window_seconds=30, max_requests=1),
        },
        now_fn=clock.now,
    )

    limiter.check(RateLimitScope.PASSWORD_RESET, "127.0.0.1")
    clock.advance(7)

    with pytest.raises(RateLimitExceededError) as exc_info:
        limiter.check(RateLimitScope.PASSWORD_RESET, "127.0.0.1")

    assert exc_info.value.retry_after_seconds == 23
