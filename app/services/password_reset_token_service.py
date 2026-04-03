from __future__ import annotations

import hashlib
import hmac
import secrets

from app.core.config import Settings
from app.core.errors import PasswordResetTokenInvalidError


class PasswordResetTokenService:
    def generate_token(self) -> str:
        raise NotImplementedError

    def hash_token(self, token: str) -> str:
        raise NotImplementedError


class OpaquePasswordResetTokenService(PasswordResetTokenService):
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def generate_token(self) -> str:
        return secrets.token_urlsafe(32)

    def hash_token(self, token: str) -> str:
        secret = self._settings.password_reset_token_pepper
        if not secret:
            raise PasswordResetTokenInvalidError()
        return hmac.new(secret.encode("utf-8"), token.encode("utf-8"), hashlib.sha256).hexdigest()
