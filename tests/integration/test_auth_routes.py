from __future__ import annotations

from sqlalchemy import select

from app.models.password_reset_token import PasswordResetToken
from app.models.user import User
from tests.integration.helpers import forgot_password, login, register, reset_password


def test_register_success(client):
    response = register(client, "user@example.com")

    assert response.status_code == 201
    body = response.json()
    assert body["email"] == "user@example.com"
    assert "id" in body


def test_register_duplicate_email(client):
    register(client, "user@example.com")

    response = register(client, "USER@example.com")

    assert response.status_code == 409
    assert response.json() == {"detail": "Email already registered"}


def test_login_success(client):
    register(client, "user@example.com")

    response = login(client, "user@example.com")

    assert response.status_code == 200
    body = response.json()
    assert "access_token" in body
    assert "refresh_token" in body
    assert body["token_type"] == "bearer"


def test_login_invalid_credentials_no_user_enumeration(client):
    register(client, "user@example.com")

    wrong_password = login(client, "user@example.com", "wrong-password-value")
    missing_user = login(client, "missing@example.com", "wrong-password-value")

    assert wrong_password.status_code == 401
    assert missing_user.status_code == 401
    assert wrong_password.json() == {"detail": "Invalid credentials"}
    assert missing_user.json() == {"detail": "Invalid credentials"}
    assert wrong_password.headers.get("WWW-Authenticate") == "Bearer"
    assert missing_user.headers.get("WWW-Authenticate") == "Bearer"


def test_login_inactive_user_same_safe_response(client, db_session):
    register(client, "user@example.com")
    user = db_session.execute(select(User).where(User.email_normalized == "user@example.com")).scalar_one()
    user.is_active = False
    db_session.commit()

    response = login(client, "user@example.com")

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials"}
    assert response.headers.get("WWW-Authenticate") == "Bearer"


def test_refresh_success(client):
    register(client, "user@example.com")
    login_response = login(client, "user@example.com")
    refresh_token = login_response.json()["refresh_token"]

    response = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})

    assert response.status_code == 200
    body = response.json()
    assert body["refresh_token"] != refresh_token
    assert body["token_type"] == "bearer"


def test_refresh_invalid_token_safe_response(client):
    response = client.post("/api/v1/auth/refresh", json={"refresh_token": "not-a-token"})

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid or expired token"}
    assert response.headers.get("WWW-Authenticate") == "Bearer"


def test_refresh_replayed_token_safe_response(client):
    register(client, "user@example.com")
    login_response = login(client, "user@example.com")
    old_refresh = login_response.json()["refresh_token"]

    first_refresh = client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
    assert first_refresh.status_code == 200

    replay_response = client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})

    assert replay_response.status_code == 401
    assert replay_response.json() == {"detail": "Invalid or expired token"}
    assert replay_response.headers.get("WWW-Authenticate") == "Bearer"


def test_logout_success(client):
    register(client, "user@example.com")
    login_response = login(client, "user@example.com")
    refresh_token = login_response.json()["refresh_token"]

    response = client.post("/api/v1/auth/logout", json={"refresh_token": refresh_token})

    assert response.status_code == 204
    assert response.text == ""


def test_refresh_inactive_user_safe_response(client, db_session):
    register(client, "user@example.com")
    login_response = login(client, "user@example.com")
    refresh_token = login_response.json()["refresh_token"]
    user = db_session.execute(select(User).where(User.email_normalized == "user@example.com")).scalar_one()
    user.is_active = False
    db_session.commit()

    response = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid or expired token"}
    assert response.headers.get("WWW-Authenticate") == "Bearer"


def test_forgot_password_always_returns_generic_200(client, reset_notifier):
    register(client, "user@example.com")

    existing = forgot_password(client, "user@example.com")
    missing = forgot_password(client, "missing@example.com")

    assert existing.status_code == 200
    assert missing.status_code == 200
    assert existing.json() == {"message": "If the account exists, a reset email has been sent."}
    assert missing.json() == {"message": "If the account exists, a reset email has been sent."}
    assert len(reset_notifier.events) == 1


def test_reset_password_success(client, reset_notifier):
    register(client, "user@example.com")
    login_response = login(client, "user@example.com")
    old_refresh_token = login_response.json()["refresh_token"]
    forgot_password(client, "user@example.com")
    raw_reset_token = reset_notifier.events[-1]["reset_token"]

    response = reset_password(client, raw_reset_token, "new correct horse battery staple")

    assert response.status_code == 200
    assert response.json() == {"message": "Password has been reset."}

    refresh_response = client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh_token})
    assert refresh_response.status_code == 401
    assert refresh_response.json() == {"detail": "Invalid or expired token"}
    assert refresh_response.headers.get("WWW-Authenticate") == "Bearer"


def test_reset_password_invalid_token_safe_response(client):
    response = reset_password(client, "not-a-real-reset-token", "new correct horse battery staple")

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid or expired reset token"}


def test_reset_password_expired_token_safe_response(client, db_session, reset_notifier):
    register(client, "user@example.com")
    forgot_password(client, "user@example.com")
    raw_reset_token = reset_notifier.events[-1]["reset_token"]
    token_record = db_session.execute(select(PasswordResetToken)).scalar_one()
    token_record.expires_at = token_record.created_at
    db_session.commit()

    response = reset_password(client, raw_reset_token, "new correct horse battery staple")

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid or expired reset token"}


def test_reset_password_reused_token_safe_response(client, reset_notifier):
    register(client, "user@example.com")
    forgot_password(client, "user@example.com")
    raw_reset_token = reset_notifier.events[-1]["reset_token"]
    first = reset_password(client, raw_reset_token, "new correct horse battery staple")
    assert first.status_code == 200

    second = reset_password(client, raw_reset_token, "another new correct horse battery staple")

    assert second.status_code == 400
    assert second.json() == {"detail": "Invalid or expired reset token"}
