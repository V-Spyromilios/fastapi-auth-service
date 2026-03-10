from __future__ import annotations

import hashlib
import hmac
import uuid
from datetime import datetime, timedelta
from typing import Any

import jwt

from app.core.config import JwtKeySet, Settings
from app.core.errors import InvalidTokenError, TokenExpiredError
from app.core.time import utc_now


class TokenService:
    def create_access_token(self, subject: str) -> str:
        raise NotImplementedError

    def create_refresh_token(self, subject: str, family_id: uuid.UUID) -> tuple[str, datetime]:
        raise NotImplementedError

    def decode_access_token(self, token: str) -> dict[str, Any]:
        raise NotImplementedError

    def decode_refresh_token(self, token: str) -> dict[str, Any]:
        raise NotImplementedError

    def hash_refresh_token(self, token: str) -> str:
        raise NotImplementedError


class JwtTokenService(TokenService):
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._keys = JwtKeySet.from_settings(settings)

    def create_access_token(self, subject: str) -> str:
        now = utc_now()
        exp = now + timedelta(minutes=self._settings.jwt_access_ttl_minutes)
        payload = {
            "sub": subject,
            "iat": int(now.timestamp()),
            "exp": int(exp.timestamp()),
            "typ": "access",
        }
        return self._encode(payload)

    def create_refresh_token(self, subject: str, family_id: uuid.UUID) -> tuple[str, datetime]:
        now = utc_now()
        exp = now + timedelta(days=self._settings.jwt_refresh_ttl_days)
        payload = {
            "sub": subject,
            "iat": int(now.timestamp()),
            "exp": int(exp.timestamp()),
            "typ": "refresh",
            "jti": str(uuid.uuid4()),
            "fam": str(family_id),
        }
        token = self._encode(payload)
        return token, exp

    def decode_access_token(self, token: str) -> dict[str, Any]:
        payload = self._decode(token)
        if payload.get("typ") != "access":
            raise InvalidTokenError()
        return payload

    def decode_refresh_token(self, token: str) -> dict[str, Any]:
        payload = self._decode(token)
        if payload.get("typ") != "refresh":
            raise InvalidTokenError()
        if "jti" not in payload or "fam" not in payload or "sub" not in payload:
            raise InvalidTokenError()
        return payload

    def hash_refresh_token(self, token: str) -> str:
        secret = self._settings.refresh_token_pepper
        if not secret:
            raise InvalidTokenError()
        digest = hmac.new(secret.encode("utf-8"), token.encode("utf-8"), hashlib.sha256).hexdigest()
        return digest

    def _encode(self, payload: dict[str, Any]) -> str:
        headers = {"kid": self._keys.private_kid}
        return jwt.encode(payload, self._keys.private_key, algorithm=self._settings.jwt_alg, headers=headers)

    def _decode(self, token: str) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            if not kid or kid not in self._keys.public_keys:
                raise InvalidTokenError()
            key = self._keys.public_keys[kid]
            return jwt.decode(
                token,
                key,
                algorithms=[self._settings.jwt_alg],
                options={"require": ["exp", "iat", "sub", "typ"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenExpiredError() from exc
        except jwt.PyJWTError as exc:
            raise InvalidTokenError() from exc
