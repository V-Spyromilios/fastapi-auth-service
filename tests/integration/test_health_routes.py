from __future__ import annotations


def test_health_reports_liveness(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "alive"}


def test_ready_reports_database_connectivity(client):
    response = client.get("/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ok"}


def test_ready_returns_503_when_database_is_unavailable(client):
    class UnreadyDatabase:
        def is_ready(self) -> bool:
            return False

    client.app.state.db = UnreadyDatabase()

    response = client.get("/ready")

    assert response.status_code == 503
    assert response.json() == {"status": "error", "database": "unavailable"}
