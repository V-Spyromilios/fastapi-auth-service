from __future__ import annotations

from datetime import timedelta
import uuid

import pytest

from app.core.errors import (
    DuplicateEmailError,
    InactiveUserError,
    InvalidCredentialsError,
    InvalidTokenError,
    PasswordResetTokenExpiredError,
    PasswordResetTokenInvalidError,
    PasswordResetTokenUsedError,
    TokenReplayError,
    UserNotFoundError,
)
from app.core.time import utc_now
from app.models.password_reset_token import PasswordResetToken
from app.core.security import RefreshTokenStatus
from app.models.user import User
from app.repositories.password_reset_token_repo import PasswordResetTokenRepository
from app.repositories.token_repo import RefreshTokenRepository
from app.services.auth_service import AuthService
from app.services.password_hasher import Argon2idHasher
from app.services.password_reset_notifier import PasswordResetNotifier
from app.services.password_reset_token_service import OpaquePasswordResetTokenService
from app.services.token_service import JwtTokenService


PASSWORD = "correct horse battery staple"
NEW_PASSWORD = "new correct horse battery staple"


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


def _service(db_session, settings, reset_notifier) -> AuthService:
    return AuthService(
        db=db_session,
        settings=settings,
        hasher=Argon2idHasher(),
        tokens=JwtTokenService(settings),
        reset_tokens=OpaquePasswordResetTokenService(settings),
        reset_notifier=reset_notifier,
    )


def test_register_success(db_session, settings, reset_notifier) -> None:
    service = _service(db_session, settings, reset_notifier)

    result = service.register("User@Example.com", PASSWORD)

    assert result.email == "User@Example.com"
    persisted = db_session.query(User).filter(User.email == "User@Example.com").one()
    assert persisted.email_normalized == "user@example.com"


def test_register_duplicate_email(db_session, settings, reset_notifier) -> None:
    _create_user(db_session, "user@example.com")
    service = _service(db_session, settings, reset_notifier)

    with pytest.raises(DuplicateEmailError):
        service.register("USER@example.com", PASSWORD)


def test_login_success(db_session, settings, reset_notifier) -> None:
    user = _create_user(db_session, "user@example.com")
    service = _service(db_session, settings, reset_notifier)

    result = service.login("user@example.com", PASSWORD)

    assert result.access_token
    assert result.refresh_token

    token_record = RefreshTokenRepository(db_session).get_by_token_hash(
        service._token_service.hash_refresh_token(result.refresh_token)
    )
    assert token_record is not None
    assert token_record.user_id == user.id
    assert token_record.status == RefreshTokenStatus.ACTIVE


def test_login_does_not_store_plaintext_refresh_token(db_session, settings, reset_notifier) -> None:
    _create_user(db_session, "user@example.com")
    service = _service(db_session, settings, reset_notifier)

    result = service.login("user@example.com", PASSWORD)
    token_record = RefreshTokenRepository(db_session).get_by_token_hash(
        service._token_service.hash_refresh_token(result.refresh_token)
    )

    assert token_record is not None
    assert token_record.token_hash != result.refresh_token


def test_login_invalid_credentials(db_session, settings, reset_notifier) -> None:
    _create_user(db_session, "user@example.com")
    service = _service(db_session, settings, reset_notifier)

    with pytest.raises(InvalidCredentialsError):
        service.login("user@example.com", "wrong-password")



def test_login_inactive_user(db_session, settings, reset_notifier) -> None:
    _create_user(db_session, "user@example.com", is_active=False)
    service = _service(db_session, settings, reset_notifier)

    with pytest.raises(InactiveUserError):
        service.login("user@example.com", PASSWORD)


def test_refresh_success(db_session, settings, reset_notifier) -> None:
    user = _create_user(db_session, "user@example.com")
    service = _service(db_session, settings, reset_notifier)
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


def test_refresh_invalid_token(db_session, settings, reset_notifier) -> None:
    _create_user(db_session, "user@example.com")
    service = _service(db_session, settings, reset_notifier)

    with pytest.raises(InvalidTokenError):
        service.refresh("not-a-token")


def test_refresh_inactive_user(db_session, settings, reset_notifier) -> None:
    user = _create_user(db_session, "user@example.com")
    service = _service(db_session, settings, reset_notifier)
    login_result = service.login("user@example.com", PASSWORD)

    user.is_active = False
    db_session.commit()

    with pytest.raises(InactiveUserError):
        service.refresh(login_result.refresh_token)


def test_refresh_replay_detection_revokes_family(db_session, settings, reset_notifier) -> None:
    _create_user(db_session, "user@example.com")
    service = _service(db_session, settings, reset_notifier)
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


def test_logout_revokes_active_token_and_is_idempotent(db_session, settings, reset_notifier) -> None:
    _create_user(db_session, "user@example.com")
    service = _service(db_session, settings, reset_notifier)
    login_result = service.login("user@example.com", PASSWORD)

    service.logout(login_result.refresh_token)
    service.logout(login_result.refresh_token)

    record = RefreshTokenRepository(db_session).get_by_token_hash(
        service._token_service.hash_refresh_token(login_result.refresh_token)
    )
    assert record is not None
    assert record.status == RefreshTokenStatus.REVOKED


def test_get_current_user_success(db_session, settings, reset_notifier) -> None:
    user = _create_user(db_session, "user@example.com")
    service = _service(db_session, settings, reset_notifier)

    result = service.get_current_user(user.id)

    assert result.id == user.id
    assert result.email == user.email


def test_get_current_user_failure_missing(db_session, settings, reset_notifier) -> None:
    service = _service(db_session, settings, reset_notifier)

    with pytest.raises(UserNotFoundError):
        service.get_current_user(uuid.uuid4())


def test_get_current_user_failure_inactive(db_session, settings, reset_notifier) -> None:
    user = _create_user(db_session, "user@example.com", is_active=False)
    service = _service(db_session, settings, reset_notifier)

    with pytest.raises(InactiveUserError):
        service.get_current_user(user.id)


def test_request_password_reset_existing_user_creates_hashed_token_and_notifies(
    db_session,
    settings,
    reset_notifier,
) -> None:
    user = _create_user(db_session, "user@example.com")
    service = _service(db_session, settings, reset_notifier)

    service.request_password_reset("user@example.com")

    assert len(reset_notifier.events) == 1
    event = reset_notifier.events[0]
    assert event["email"] == "user@example.com"

    repo = PasswordResetTokenRepository(db_session)
    token_record = repo.get_by_token_hash(service._password_reset_token_service.hash_token(event["reset_token"]))
    assert token_record is not None
    assert token_record.user_id == user.id
    assert token_record.token_hash != event["reset_token"]


def test_request_password_reset_missing_user_is_silent(db_session, settings, reset_notifier) -> None:
    service = _service(db_session, settings, reset_notifier)

    service.request_password_reset("missing@example.com")

    assert reset_notifier.events == []


def test_request_password_reset_notifier_failure_is_silent(db_session, settings) -> None:
    class FailingNotifier(PasswordResetNotifier):
        def send_password_reset(self, *, email: str, reset_token: str) -> None:
            raise RuntimeError("delivery failed")

    _create_user(db_session, "user@example.com")
    service = AuthService(
        db=db_session,
        settings=settings,
        hasher=Argon2idHasher(),
        tokens=JwtTokenService(settings),
        reset_tokens=OpaquePasswordResetTokenService(settings),
        reset_notifier=FailingNotifier(),
    )

    service.request_password_reset("user@example.com")

    tokens = PasswordResetTokenRepository(db_session).list_by_user_id(
        db_session.query(User).filter(User.email_normalized == "user@example.com").one().id
    )
    assert len(tokens) == 1


def test_request_password_reset_revokes_prior_active_tokens(db_session, settings, reset_notifier) -> None:
    user = _create_user(db_session, "user@example.com")
    service = _service(db_session, settings, reset_notifier)
    repo = PasswordResetTokenRepository(db_session)

    first_raw = service._password_reset_token_service.generate_token()
    first = PasswordResetToken(
        user_id=user.id,
        token_hash=service._password_reset_token_service.hash_token(first_raw),
        expires_at=utc_now() + timedelta(minutes=30),
    )
    db_session.add(first)
    db_session.commit()

    service.request_password_reset("user@example.com")

    tokens = repo.list_by_user_id(user.id)
    assert len(tokens) == 2
    revoked = [token for token in tokens if token.revoked_at is not None]
    active = [token for token in tokens if token.revoked_at is None and token.used_at is None]
    assert len(revoked) == 1
    assert len(active) == 1


def test_reset_password_success_updates_password_and_invalidates_sessions(
    db_session,
    settings,
    reset_notifier,
) -> None:
    user = _create_user(db_session, "user@example.com")
    service = _service(db_session, settings, reset_notifier)
    login_result = service.login("user@example.com", PASSWORD)
    service.request_password_reset("user@example.com")
    raw_reset_token = reset_notifier.events[0]["reset_token"]

    service.reset_password(raw_reset_token, NEW_PASSWORD)

    db_session.refresh(user)
    assert user.password_changed_at is not None
    assert service._hasher.verify(NEW_PASSWORD, user.password_hash) is True

    reset_record = PasswordResetTokenRepository(db_session).get_by_token_hash(
        service._password_reset_token_service.hash_token(raw_reset_token)
    )
    assert reset_record is not None
    assert reset_record.used_at is not None

    refresh_record = RefreshTokenRepository(db_session).get_by_token_hash(
        service._token_service.hash_refresh_token(login_result.refresh_token)
    )
    assert refresh_record is not None
    assert refresh_record.status == RefreshTokenStatus.REVOKED


def test_reset_password_invalid_token(db_session, settings, reset_notifier) -> None:
    _create_user(db_session, "user@example.com")
    service = _service(db_session, settings, reset_notifier)

    with pytest.raises(PasswordResetTokenInvalidError):
        service.reset_password("not-a-real-reset-token", NEW_PASSWORD)


def test_reset_password_expired_token(db_session, settings, reset_notifier) -> None:
    user = _create_user(db_session, "user@example.com")
    service = _service(db_session, settings, reset_notifier)
    raw_token = service._password_reset_token_service.generate_token()
    token_record = PasswordResetToken(
        user_id=user.id,
        token_hash=service._password_reset_token_service.hash_token(raw_token),
        expires_at=utc_now() - timedelta(minutes=1),
    )
    db_session.add(token_record)
    db_session.commit()

    with pytest.raises(PasswordResetTokenExpiredError):
        service.reset_password(raw_token, NEW_PASSWORD)


def test_reset_password_reused_token(db_session, settings, reset_notifier) -> None:
    user = _create_user(db_session, "user@example.com")
    service = _service(db_session, settings, reset_notifier)
    raw_token = service._password_reset_token_service.generate_token()
    token_record = PasswordResetToken(
        user_id=user.id,
        token_hash=service._password_reset_token_service.hash_token(raw_token),
        expires_at=utc_now() + timedelta(minutes=30),
        used_at=utc_now(),
    )
    db_session.add(token_record)
    db_session.commit()

    with pytest.raises(PasswordResetTokenUsedError):
        service.reset_password(raw_token, NEW_PASSWORD)


def test_get_current_user_rejects_stale_access_token_after_password_change(
    db_session,
    settings,
    reset_notifier,
) -> None:
    user = _create_user(db_session, "user@example.com")
    service = _service(db_session, settings, reset_notifier)
    issued_at = int(utc_now().timestamp())
    user.password_changed_at = utc_now() + timedelta(minutes=1)
    db_session.commit()

    with pytest.raises(InvalidTokenError):
        service.get_current_user(user.id, token_issued_at=issued_at)
