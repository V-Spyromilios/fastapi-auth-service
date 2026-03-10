from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.refresh_token import RefreshToken


class RefreshTokenRepository:
    def __init__(self, db: Session) -> None:
        self._db = db

    def get_by_id(self, token_id: UUID) -> RefreshToken | None:
        return self._db.get(RefreshToken, token_id)

    def get_by_token_hash(self, token_hash: str) -> RefreshToken | None:
        stmt = select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        return self._db.execute(stmt).scalar_one_or_none()

    def list_by_family_id(self, family_id: UUID) -> list[RefreshToken]:
        stmt = select(RefreshToken).where(RefreshToken.family_id == family_id)
        return list(self._db.execute(stmt).scalars().all())

    def add(self, token: RefreshToken) -> None:
        self._db.add(token)
