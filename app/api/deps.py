from __future__ import annotations

import uuid
from collections.abc import Generator

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.errors import (
    InactiveUserError,
    InvalidTokenError,
    TokenExpiredError,
    UnauthorizedError,
    UserNotFoundError,
)
from app.core.rate_limit import RateLimiter
from app.db.session import Database
from app.schemas.users import UserPublic
from app.services.auth_service import AuthService
from app.services.password_hasher import Argon2idHasher, PasswordHasher
from app.services.password_reset_notifier import NoopPasswordResetNotifier, PasswordResetNotifier
from app.services.password_reset_token_service import (
    OpaquePasswordResetTokenService,
    PasswordResetTokenService,
)
from app.services.token_service import JwtTokenService, TokenService


def get_settings_dep() -> Settings:
    return get_settings()


def get_db_dep(request: Request) -> Generator[Session, None, None]:
    db: Database = request.app.state.db
    yield from db.get_db()


def get_rate_limiter_dep(request: Request) -> RateLimiter:
    limiter: RateLimiter = request.app.state.rate_limiter
    return limiter


def get_password_hasher_dep() -> PasswordHasher:
    return Argon2idHasher()


def get_token_service_dep(settings: Settings = Depends(get_settings_dep)) -> TokenService:
    return JwtTokenService(settings)


def get_password_reset_token_service_dep(
    settings: Settings = Depends(get_settings_dep),
) -> PasswordResetTokenService:
    return OpaquePasswordResetTokenService(settings)


def get_password_reset_notifier_dep() -> PasswordResetNotifier:
    return NoopPasswordResetNotifier()


def get_auth_service_dep(
    settings: Settings = Depends(get_settings_dep),
    db: Session = Depends(get_db_dep),
    hasher: PasswordHasher = Depends(get_password_hasher_dep),
    tokens: TokenService = Depends(get_token_service_dep),
    reset_tokens: PasswordResetTokenService = Depends(
        get_password_reset_token_service_dep
    ),
    reset_notifier: PasswordResetNotifier = Depends(get_password_reset_notifier_dep),
) -> AuthService:
    return AuthService(
        db=db,
        settings=settings,
        hasher=hasher,
        tokens=tokens,
        reset_tokens=reset_tokens,
        reset_notifier=reset_notifier,
    )


_bearer = HTTPBearer(auto_error=False)


def get_current_user_dep(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    tokens: TokenService = Depends(get_token_service_dep),
    auth: AuthService = Depends(get_auth_service_dep),
) -> UserPublic:
    if not credentials or not credentials.credentials:
        raise UnauthorizedError()
    token = credentials.credentials
    try:
        payload = tokens.decode_access_token(token)
        subject = payload.get("sub")
        issued_at = int(payload.get("iat"))
        user_id = uuid.UUID(subject)
        return auth.get_current_user(user_id, token_issued_at=issued_at)
    except (
        InvalidTokenError,
        TokenExpiredError,
        ValueError,
        TypeError,
        UserNotFoundError,
        InactiveUserError,
    ) as exc:
        raise UnauthorizedError() from exc
