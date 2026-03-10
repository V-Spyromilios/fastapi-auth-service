from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.user import User


class UserRepository:
    def __init__(self, db: Session) -> None:
        self._db = db

    def get_by_id(self, user_id: UUID) -> User | None:
        return self._db.get(User, user_id)

    def get_by_email_normalized(self, email_normalized: str) -> User | None:
        stmt = select(User).where(User.email_normalized == email_normalized)
        return self._db.execute(stmt).scalar_one_or_none()

    def add(self, user: User) -> None:
        self._db.add(user)
