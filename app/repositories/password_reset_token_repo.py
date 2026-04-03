from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.password_reset_token import PasswordResetToken


class PasswordResetTokenRepository:
    def __init__(self, db: Session) -> None:
        self._db = db

    def get_by_token_hash(self, token_hash: str) -> PasswordResetToken | None:
        stmt = select(PasswordResetToken).where(PasswordResetToken.token_hash == token_hash)
        return self._db.execute(stmt).scalar_one_or_none()

    def list_by_user_id(self, user_id: UUID) -> list[PasswordResetToken]:
        stmt = select(PasswordResetToken).where(PasswordResetToken.user_id == user_id)
        return list(self._db.execute(stmt).scalars().all())

    def add(self, token: PasswordResetToken) -> None:
        self._db.add(token)
