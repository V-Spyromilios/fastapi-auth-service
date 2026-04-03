from __future__ import annotations

PASSWORD = "correct horse battery staple"


def register(client, email: str, password: str = PASSWORD):
    return client.post("/api/v1/auth/register", json={"email": email, "password": password})


def login(client, email: str, password: str = PASSWORD):
    return client.post("/api/v1/auth/login", json={"email": email, "password": password})


def forgot_password(client, email: str):
    return client.post("/api/v1/auth/forgot-password", json={"email": email})


def reset_password(client, reset_token: str, new_password: str):
    return client.post(
        "/api/v1/auth/reset-password",
        json={"reset_token": reset_token, "new_password": new_password},
    )
