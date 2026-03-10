from __future__ import annotations

from tests.integration.helpers import login, register


def test_get_me_success(client):
    register(client, "user@example.com")
    login_response = login(client, "user@example.com")
    access_token = login_response.json()["access_token"]

    response = client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {access_token}"})

    assert response.status_code == 200
    body = response.json()
    assert body["email"] == "user@example.com"
    assert "id" in body


def test_get_me_unauthorized(client):
    response = client.get("/api/v1/users/me")

    assert response.status_code == 401
    assert response.json() == {"detail": "Unauthorized"}
    assert response.headers.get("WWW-Authenticate") == "Bearer"


def test_get_me_invalid_bearer_token(client):
    response = client.get("/api/v1/users/me", headers={"Authorization": "Bearer not-a-token"})

    assert response.status_code == 401
    assert response.json() == {"detail": "Unauthorized"}
    assert response.headers.get("WWW-Authenticate") == "Bearer"
