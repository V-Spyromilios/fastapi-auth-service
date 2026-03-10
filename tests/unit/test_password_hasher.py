from __future__ import annotations

from app.services.password_hasher import Argon2idHasher


def test_argon2id_hash_and_verify() -> None:
    hasher = Argon2idHasher()
    password = "correct horse battery staple"

    password_hash = hasher.hash(password)

    assert password_hash != password
    assert hasher.verify(password, password_hash) is True
    assert hasher.verify("wrong password", password_hash) is False
