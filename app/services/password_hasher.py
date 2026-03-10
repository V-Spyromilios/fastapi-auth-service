from __future__ import annotations

from passlib.hash import argon2


class PasswordHasher:
    def hash(self, password: str) -> str:
        raise NotImplementedError

    def verify(self, password: str, password_hash: str) -> bool:
        raise NotImplementedError


class Argon2idHasher(PasswordHasher):
    def __init__(self) -> None:
        self._hasher = argon2.using(type="ID", time_cost=3, memory_cost=65536, parallelism=2)

    def hash(self, password: str) -> str:
        return self._hasher.hash(password)

    def verify(self, password: str, password_hash: str) -> bool:
        return self._hasher.verify(password, password_hash)
