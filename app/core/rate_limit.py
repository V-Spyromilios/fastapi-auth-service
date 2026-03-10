from __future__ import annotations

from typing import Protocol


class RateLimiter(Protocol):
    def check(self, key: str) -> None:
        """Raise an exception if rate limit is exceeded."""
        raise NotImplementedError


class NoopRateLimiter:
    def check(self, key: str) -> None:
        return None
