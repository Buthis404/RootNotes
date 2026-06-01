"""Tests for authentication endpoints."""
from fastapi.testclient import TestClient


def test_auth_status_uninitialized(client: TestClient):
    resp = client.get("/api/auth/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "initialized" in data


def test_setup_creates_admin(client: TestClient):
    resp = client.post("/api/auth/setup", json={"username": "admin", "password": "TestPass1234!"})  # NOSONAR
    # Either 201 (first setup) or 403 (already initialized)
    assert resp.status_code in (201, 403)


def test_login_wrong_password(client: TestClient):
    # Ensure user exists first
    client.post("/api/auth/setup", json={"username": "admin", "password": "TestPass1234!"})  # NOSONAR
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "wrongpassword"})  # NOSONAR
    assert resp.status_code == 401


def test_login_nonexistent_user(client: TestClient):
    resp = client.post("/api/auth/login", json={"username": "nobody", "password": "pass"})  # NOSONAR
    assert resp.status_code == 401


def test_me_without_token(client: TestClient):
    resp = client.get("/api/auth/me")
    assert resp.status_code == 401


def test_protected_endpoint_without_token(client: TestClient):
    resp = client.get("/api/notes")
    assert resp.status_code == 401


def test_health_endpoint_public(client: TestClient):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] in ("ok", "degraded")
