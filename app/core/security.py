from __future__ import annotations

from enum import StrEnum


class RefreshTokenStatus(StrEnum):
    ACTIVE = "active"
    ROTATED = "rotated"
    REVOKED = "revoked"
