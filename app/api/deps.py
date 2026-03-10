from __future__ import annotations

from collections.abc import Generator

import uuid

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.errors import (
    InactiveUserError,
    InvalidTokenError,
    TokenExpiredError,
    UserNotFoundError,
)
from app.db.session import Database
from app.schemas.users import UserPublic
from app.services.auth_service import AuthService
from app.services.password_hasher import Argon2idHasher, PasswordHasher
from app.services.token_service import JwtTokenService, TokenService


def get_settings_dep() -> Settings:
    return get_settings()


def get_db_dep(request: Request) -> Generator[Session, None, None]:
    db: Database = request.app.state.db
    yield from db.get_db()


def get_password_hasher_dep() -> PasswordHasher:
    return Argon2idHasher()


def get_token_service_dep(settings: Settings = Depends(get_settings_dep)) -> TokenService:
    return JwtTokenService(settings)


def get_auth_service_dep(
    db: Session = Depends(get_db_dep),
    hasher: PasswordHasher = Depends(get_password_hasher_dep),
    tokens: TokenService = Depends(get_token_service_dep),
) -> AuthService:
    return AuthService(db=db, hasher=hasher, tokens=tokens)


_bearer = HTTPBearer(auto_error=False)


def get_current_user_dep(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    tokens: TokenService = Depends(get_token_service_dep),
    auth: AuthService = Depends(get_auth_service_dep),
) -> UserPublic:
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = credentials.credentials
    try:
        payload = tokens.decode_access_token(token)
        subject = payload.get("sub")
        user_id = uuid.UUID(subject)
        return auth.get_current_user(user_id)
    except (InvalidTokenError, TokenExpiredError, ValueError, TypeError, UserNotFoundError, InactiveUserError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Bearer"},
        )
