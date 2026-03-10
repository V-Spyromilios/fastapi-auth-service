from __future__ import annotations

import uuid
from datetime import timedelta

import jwt
import pytest

from app.core.errors import InvalidTokenError, TokenExpiredError
from app.core.time import utc_now
from app.services.token_service import JwtTokenService


def test_access_token_creation_and_decoding(settings) -> None:
    service = JwtTokenService(settings)

    token = service.create_access_token("user-123")
    payload = service.decode_access_token(token)

    assert payload["sub"] == "user-123"
    assert payload["typ"] == "access"
    assert payload["exp"] > payload["iat"]


def test_refresh_token_creation_and_decoding(settings) -> None:
    service = JwtTokenService(settings)
    family_id = uuid.uuid4()

    token, expires_at = service.create_refresh_token("user-123", family_id)
    payload = service.decode_refresh_token(token)

    assert payload["sub"] == "user-123"
    assert payload["typ"] == "refresh"
    assert payload["fam"] == str(family_id)
    assert "jti" in payload
    assert expires_at > utc_now()


def test_refresh_token_hashing_is_deterministic_and_secret_bound(settings) -> None:
    service = JwtTokenService(settings)

    first = service.hash_refresh_token("refresh-token-value")
    second = service.hash_refresh_token("refresh-token-value")
    third = service.hash_refresh_token("different-refresh-token")

    assert first == second
    assert first != third


def test_decode_access_token_rejects_expired_token(settings) -> None:
    service = JwtTokenService(settings)
    now = utc_now()
    payload = {
        "sub": "user-123",
        "iat": int((now - timedelta(minutes=2)).timestamp()),
        "exp": int((now - timedelta(minutes=1)).timestamp()),
        "typ": "access",
    }
    token = jwt.encode(
        payload,
        settings.jwt_private_key,
        algorithm=settings.jwt_alg,
        headers={"kid": settings.jwt_private_key_kid},
    )

    with pytest.raises(TokenExpiredError):
        service.decode_access_token(token)


def test_decode_refresh_token_rejects_malformed_token(settings) -> None:
    service = JwtTokenService(settings)

    with pytest.raises(InvalidTokenError):
        service.decode_refresh_token("not-a-jwt")
