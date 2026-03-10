from __future__ import annotations

PASSWORD = "correct horse battery staple"


def register(client, email: str, password: str = PASSWORD):
    return client.post("/api/v1/auth/register", json={"email": email, "password": password})


def login(client, email: str, password: str = PASSWORD):
    return client.post("/api/v1/auth/login", json={"email": email, "password": password})
