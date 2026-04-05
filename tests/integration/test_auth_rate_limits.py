from __future__ import annotations

from app.core.rate_limit import InMemoryFixedWindowRateLimiter, RateLimitRule, RateLimitScope
from tests.integration.helpers import forgot_password, login, register


class FakeClock:
    def __init__(self, start: float = 0.0) -> None:
        self._now = start

    def now(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


def _install_rate_limiter(
    client,
    *,
    login_max_requests: int = 2,
    login_window_seconds: int = 60,
    password_reset_max_requests: int = 2,
    password_reset_window_seconds: int = 60,
) -> FakeClock:
    clock = FakeClock()
    client.app.state.rate_limiter = InMemoryFixedWindowRateLimiter(
        {
            RateLimitScope.LOGIN: RateLimitRule(
                window_seconds=login_window_seconds,
                max_requests=login_max_requests,
            ),
            RateLimitScope.PASSWORD_RESET: RateLimitRule(
                window_seconds=password_reset_window_seconds,
                max_requests=password_reset_max_requests,
            ),
        },
        now_fn=clock.now,
    )
    return clock


def test_login_is_limited_after_max_attempts(client):
    register(client, "user@example.com")
    _install_rate_limiter(client, login_max_requests=2)

    first = login(client, "user@example.com", "wrong-password-value")
    second = login(client, "missing@example.com", "wrong-password-value")
    third = login(client, "user@example.com", "wrong-password-value")

    assert first.status_code == 401
    assert second.status_code == 401
    assert third.status_code == 429
    assert third.json() == {"detail": "Too many requests. Please try again later."}
    assert third.headers.get("Retry-After") == "60"


def test_forgot_password_is_limited_after_max_attempts_without_user_enumeration(client):
    register(client, "user@example.com")
    _install_rate_limiter(client, password_reset_max_requests=2)

    first = forgot_password(client, "user@example.com")
    second = forgot_password(client, "missing@example.com")
    third = forgot_password(client, "user@example.com")

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json() == {"message": "If the account exists, a reset email has been sent."}
    assert second.json() == {"message": "If the account exists, a reset email has been sent."}
    assert third.status_code == 429
    assert third.json() == {"detail": "Too many requests. Please try again later."}
    assert third.headers.get("Retry-After") == "60"


def test_login_limit_resets_after_the_window(client):
    register(client, "user@example.com")
    clock = _install_rate_limiter(
        client,
        login_max_requests=1,
        login_window_seconds=10,
    )

    first = login(client, "user@example.com", "wrong-password-value")
    second = login(client, "user@example.com", "wrong-password-value")
    clock.advance(10)
    third = login(client, "user@example.com", "wrong-password-value")

    assert first.status_code == 401
    assert second.status_code == 429
    assert second.headers.get("Retry-After") == "10"
    assert third.status_code == 401
