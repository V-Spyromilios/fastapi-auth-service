from __future__ import annotations

import uuid

import pytest

from app.core.errors import (
    DuplicateEmailError,
    InactiveUserError,
    InvalidCredentialsError,
    InvalidTokenError,
    TokenReplayError,
    UserNotFoundError,
)
from app.core.security import RefreshTokenStatus
from app.models.user import User
from app.repositories.token_repo import RefreshTokenRepository
from app.services.auth_service import AuthService
from app.services.password_hasher import Argon2idHasher
from app.services.token_service import JwtTokenService


PASSWORD = "correct horse battery staple"


def _create_user(db_session, email: str, *, is_active: bool = True) -> User:
    hasher = Argon2idHasher()
    user = User(
        email=email.strip(),
        email_normalized=email.strip().lower(),
        password_hash=hasher.hash(PASSWORD),
        is_active=is_active,
    )
    db_session.add(user)
    db_session.commit()
    return user


def _service(db_session, settings) -> AuthService:
    return AuthService(db=db_session, hasher=Argon2idHasher(), tokens=JwtTokenService(settings))


def test_register_success(db_session, settings) -> None:
    service = _service(db_session, settings)

    result = service.register("User@Example.com", PASSWORD)

    assert result.email == "User@example.com"
    persisted = db_session.query(User).filter(User.email == "User@Example.com").one()
    assert persisted.email_normalized == "user@example.com"


def test_register_duplicate_email(db_session, settings) -> None:
    _create_user(db_session, "user@example.com")
    service = _service(db_session, settings)

    with pytest.raises(DuplicateEmailError):
        service.register("USER@example.com", PASSWORD)


def test_login_success(db_session, settings) -> None:
    user = _create_user(db_session, "user@example.com")
    service = _service(db_session, settings)

    result = service.login("user@example.com", PASSWORD)

    assert result.access_token
    assert result.refresh_token

    token_record = RefreshTokenRepository(db_session).get_by_token_hash(
        service._token_service.hash_refresh_token(result.refresh_token)
    )
    assert token_record is not None
    assert token_record.user_id == user.id
    assert token_record.status == RefreshTokenStatus.ACTIVE


def test_login_does_not_store_plaintext_refresh_token(db_session, settings) -> None:
    _create_user(db_session, "user@example.com")
    service = _service(db_session, settings)

    result = service.login("user@example.com", PASSWORD)
    token_record = RefreshTokenRepository(db_session).get_by_token_hash(
        service._token_service.hash_refresh_token(result.refresh_token)
    )

    assert token_record is not None
    assert token_record.token_hash != result.refresh_token


def test_login_invalid_credentials(db_session, settings) -> None:
    _create_user(db_session, "user@example.com")
    service = _service(db_session, settings)

    with pytest.raises(InvalidCredentialsError):
        service.login("user@example.com", "wrong-password")



def test_login_inactive_user(db_session, settings) -> None:
    _create_user(db_session, "user@example.com", is_active=False)
    service = _service(db_session, settings)

    with pytest.raises(InactiveUserError):
        service.login("user@example.com", PASSWORD)


def test_refresh_success(db_session, settings) -> None:
    user = _create_user(db_session, "user@example.com")
    service = _service(db_session, settings)
    login_result = service.login("user@example.com", PASSWORD)

    refresh_result = service.refresh(login_result.refresh_token)

    assert refresh_result.access_token
    assert refresh_result.refresh_token != login_result.refresh_token

    repo = RefreshTokenRepository(db_session)
    old_record = repo.get_by_token_hash(service._token_service.hash_refresh_token(login_result.refresh_token))
    new_record = repo.get_by_token_hash(service._token_service.hash_refresh_token(refresh_result.refresh_token))

    assert old_record is not None
    assert old_record.status == RefreshTokenStatus.ROTATED
    assert new_record is not None
    assert new_record.user_id == user.id
    assert new_record.status == RefreshTokenStatus.ACTIVE


def test_refresh_invalid_token(db_session, settings) -> None:
    _create_user(db_session, "user@example.com")
    service = _service(db_session, settings)

    with pytest.raises(InvalidTokenError):
        service.refresh("not-a-token")


def test_refresh_inactive_user(db_session, settings) -> None:
    user = _create_user(db_session, "user@example.com")
    service = _service(db_session, settings)
    login_result = service.login("user@example.com", PASSWORD)

    user.is_active = False
    db_session.commit()

    with pytest.raises(InactiveUserError):
        service.refresh(login_result.refresh_token)


def test_refresh_replay_detection_revokes_family(db_session, settings) -> None:
    _create_user(db_session, "user@example.com")
    service = _service(db_session, settings)
    login_result = service.login("user@example.com", PASSWORD)

    first_refresh = service.refresh(login_result.refresh_token)
    assert first_refresh.refresh_token

    with pytest.raises(TokenReplayError):
        service.refresh(login_result.refresh_token)

    repo = RefreshTokenRepository(db_session)
    old_record = repo.get_by_token_hash(service._token_service.hash_refresh_token(login_result.refresh_token))
    assert old_record is not None

    family_records = repo.list_by_family_id(old_record.family_id)
    assert family_records
    assert all(record.status == RefreshTokenStatus.REVOKED for record in family_records)


def test_logout_revokes_active_token_and_is_idempotent(db_session, settings) -> None:
    _create_user(db_session, "user@example.com")
    service = _service(db_session, settings)
    login_result = service.login("user@example.com", PASSWORD)

    service.logout(login_result.refresh_token)
    service.logout(login_result.refresh_token)

    record = RefreshTokenRepository(db_session).get_by_token_hash(
        service._token_service.hash_refresh_token(login_result.refresh_token)
    )
    assert record is not None
    assert record.status == RefreshTokenStatus.REVOKED


def test_get_current_user_success(db_session, settings) -> None:
    user = _create_user(db_session, "user@example.com")
    service = _service(db_session, settings)

    result = service.get_current_user(user.id)

    assert result.id == user.id
    assert result.email == user.email


def test_get_current_user_failure_missing(db_session, settings) -> None:
    service = _service(db_session, settings)

    with pytest.raises(UserNotFoundError):
        service.get_current_user(uuid.uuid4())


def test_get_current_user_failure_inactive(db_session, settings) -> None:
    user = _create_user(db_session, "user@example.com", is_active=False)
    service = _service(db_session, settings)

    with pytest.raises(InactiveUserError):
        service.get_current_user(user.id)
