"""Webhooks API integration tests — token management, event ingestion."""
import pytest
from fastapi.testclient import TestClient

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
TS = "2025-01-01T00:00:00Z"

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200, r.text
    r = module_client.post("/api/projects", json={"name": "Webhooks Test", "added": TS, "status": "active"})
    assert r.status_code == 201, r.text
    _state["pid"] = r.json()["id"]
    yield
    module_client.post("/api/auth/logout")


class TestWebhookToken:
    def test_get_webhook_initially_empty(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/webhook")
        assert r.status_code == 200
        data = r.json()
        assert "token" in data
        assert "url" in data

    def test_regenerate_webhook_token(self, module_client: TestClient):
        r = module_client.post(f"/api/projects/{_state['pid']}/webhook/regenerate")
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["token"]
        assert data["url"]
        _state["token"] = data["token"]

    def test_get_webhook_after_regenerate(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/webhook")
        assert r.status_code == 200
        assert r.json()["token"] == _state["token"]

    def test_webhook_nonexistent_project_404(self, module_client: TestClient):
        r = module_client.get("/api/projects/prj_nonexistent/webhook")
        assert r.status_code == 404


class TestWebhookIngestion:
    def test_receive_cred_event(self, module_client: TestClient):
        token = _state["token"]
        r = module_client.post(f"/api/webhooks/{token}", json={
            "type": "cred",
            "username": "svc_admin",
            "secret": "NTHash12345",
            "domain": "corp.local",
            "ip": "10.0.0.50",
        })
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["ok"] is True

    def test_receive_finding_event(self, module_client: TestClient):
        token = _state["token"]
        r = module_client.post(f"/api/webhooks/{token}", json={
            "type": "finding",
            "title": "Privilege Escalation",
            "severity": "critical",
            "ip": "10.0.0.50",
            "description": "Local admin obtained",
        })
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["ok"] is True
        assert "finding" in data["results"]

    def test_receive_cred_event_duplicate(self, module_client: TestClient):
        token = _state["token"]
        r = module_client.post(f"/api/webhooks/{token}", json={
            "type": "cred",
            "username": "svc_admin",
            "secret": "NTHash12345",
            "domain": "corp.local",
            "ip": "10.0.0.50",
        })
        assert r.status_code == 200
        assert r.json()["results"].get("cred") in ("created", "exists")

    def test_receive_implant_event_no_ip(self, module_client: TestClient):
        token = _state["token"]
        r = module_client.post(f"/api/webhooks/{token}", json={
            "type": "implant",
        })
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_invalid_token_404(self, module_client: TestClient):
        r = module_client.post("/api/webhooks/invalid_token_xyz", json={
            "type": "beacon",
            "ip": "10.0.0.1",
        })
        assert r.status_code == 404


class TestCheckWebhookToken:
    def test_check_valid_token(self, module_client: TestClient):
        r = module_client.get(f"/api/webhooks/{_state['token']}")
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert "project" in data

    def test_check_invalid_token_404(self, module_client: TestClient):
        r = module_client.get("/api/webhooks/invalid_token_xyz")
        assert r.status_code == 404
