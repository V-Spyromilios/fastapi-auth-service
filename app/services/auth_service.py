from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.core.errors import (
    DuplicateEmailError,
    InactiveUserError,
    InvalidCredentialsError,
    InvalidTokenError,
    TokenReplayError,
    UserNotFoundError,
)
from app.core.security import RefreshTokenStatus
from app.core.time import utc_now
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.repositories.token_repo import RefreshTokenRepository
from app.repositories.user_repo import UserRepository
from app.schemas.auth import TokenPair
from app.schemas.users import UserPublic
from app.services.password_hasher import PasswordHasher
from app.services.token_service import TokenService


class AuthService:
    def __init__(self, db: Session, hasher: PasswordHasher, tokens: TokenService) -> None:
        self._db = db
        self._users = UserRepository(db)
        self._tokens = RefreshTokenRepository(db)
        self._hasher = hasher
        self._token_service = tokens

    def register(self, email: str, password: str) -> UserPublic:
        email_clean = email.strip()
        email_normalized = email_clean.lower()
        if self._users.get_by_email_normalized(email_normalized):
            raise DuplicateEmailError()

        password_hash = self._hasher.hash(password)
        user = User(
            email=email_clean,
            email_normalized=email_normalized,
            password_hash=password_hash,
            is_active=True,
        )
        self._users.add(user)
        try:
            self._db.commit()
        except Exception:
            self._db.rollback()
            raise
        return UserPublic(id=user.id, email=user.email, created_at=user.created_at)

    def login(self, email: str, password: str) -> TokenPair:
        email_clean = email.strip()
        email_normalized = email_clean.lower()
        user = self._users.get_by_email_normalized(email_normalized)
        if not user or not self._hasher.verify(password, user.password_hash):
            raise InvalidCredentialsError()
        if not user.is_active:
            raise InactiveUserError()

        access_token = self._token_service.create_access_token(str(user.id))
        family_id = uuid.uuid4()
        refresh_token, expires_at = self._token_service.create_refresh_token(str(user.id), family_id)
        token_hash = self._token_service.hash_refresh_token(refresh_token)

        token_record = RefreshToken(
            user_id=user.id,
            family_id=family_id,
            token_hash=token_hash,
            status=RefreshTokenStatus.ACTIVE,
            expires_at=expires_at,
        )
        self._tokens.add(token_record)
        try:
            self._db.commit()
        except Exception:
            self._db.rollback()
            raise
        return TokenPair(access_token=access_token, refresh_token=refresh_token)

    def refresh(self, refresh_token: str) -> TokenPair:
        payload = self._token_service.decode_refresh_token(refresh_token)
        token_hash = self._token_service.hash_refresh_token(refresh_token)
        token_record = self._tokens.get_by_token_hash(token_hash)
        if not token_record:
            raise InvalidTokenError()

        if token_record.status != RefreshTokenStatus.ACTIVE:
            self._revoke_family(token_record.family_id)
            try:
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise
            raise TokenReplayError()

        if token_record.expires_at <= utc_now():
            raise InvalidTokenError()

        subject = payload.get("sub")
        fam_value = payload.get("fam")
        if not isinstance(subject, str) or not subject:
            raise InvalidTokenError()
        try:
            family_id = uuid.UUID(fam_value)
        except Exception as exc:
            raise InvalidTokenError() from exc
        if token_record.family_id != family_id:
            raise InvalidTokenError()

        user = self._users.get_by_id(token_record.user_id)
        if not user:
            raise InvalidTokenError()
        if not user.is_active:
            raise InactiveUserError()

        token_record.status = RefreshTokenStatus.ROTATED
        token_record.rotated_at = utc_now()

        access_token = self._token_service.create_access_token(subject)
        new_refresh_token, expires_at = self._token_service.create_refresh_token(subject, family_id)
        new_token_hash = self._token_service.hash_refresh_token(new_refresh_token)
        new_record = RefreshToken(
            user_id=token_record.user_id,
            family_id=family_id,
            token_hash=new_token_hash,
            status=RefreshTokenStatus.ACTIVE,
            expires_at=expires_at,
        )
        self._tokens.add(new_record)
        try:
            self._db.commit()
        except Exception:
            self._db.rollback()
            raise
        return TokenPair(access_token=access_token, refresh_token=new_refresh_token)

    def logout(self, refresh_token: str) -> None:
        try:
            self._token_service.decode_refresh_token(refresh_token)
        except InvalidTokenError:
            return

        token_hash = self._token_service.hash_refresh_token(refresh_token)
        token_record = self._tokens.get_by_token_hash(token_hash)
        if not token_record:
            return

        if token_record.status == RefreshTokenStatus.ACTIVE:
            token_record.status = RefreshTokenStatus.REVOKED
            token_record.revoked_at = utc_now()
            try:
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise

    def get_current_user(self, user_id: uuid.UUID) -> UserPublic:
        user = self._users.get_by_id(user_id)
        if not user:
            raise UserNotFoundError()
        if not user.is_active:
            raise InactiveUserError()
        return UserPublic(id=user.id, email=user.email, created_at=user.created_at)

    def _revoke_family(self, family_id: uuid.UUID) -> None:
        now = utc_now()
        for token in self._tokens.list_by_family_id(family_id):
            token.status = RefreshTokenStatus.REVOKED
            token.revoked_at = now
