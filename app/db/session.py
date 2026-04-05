from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
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

    def is_ready(self) -> bool:
        try:
            with self._engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            return True
        except SQLAlchemyError:
            return False

    def get_db(self) -> Generator[Session, None, None]:
        db = self.session()
        try:
            yield db
        finally:
            db.close()
