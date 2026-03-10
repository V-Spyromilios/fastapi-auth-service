from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings


class Database:
    def __init__(self, settings: Settings) -> None:
        self._engine = create_engine(settings.database_url, pool_pre_ping=True)
        self._session_factory = sessionmaker(bind=self._engine, autoflush=False, autocommit=False)

    @property
    def engine(self) -> Engine:
        return self._engine

    def session(self) -> Session:
        return self._session_factory()

    def get_db(self) -> Generator[Session, None, None]:
        db = self.session()
        try:
            yield db
        finally:
            db.close()
