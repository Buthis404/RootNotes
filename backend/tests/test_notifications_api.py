"""Comprehensive tests for the notifications API endpoints."""
import pytest
from fastapi.testclient import TestClient

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    yield
    module_client.post("/api/auth/logout")


class TestGetConfig:
    def test_get_config_default(self, module_client: TestClient):
        r = module_client.get("/api/notifications/config")
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, dict)


class TestUpdateConfig:
    def test_update_config(self, module_client: TestClient):
        r = module_client.put("/api/notifications/config", json={
            "telegram": {"enabled": True, "token": "123", "chat_id": "456"},
            "slack": {"enabled": False},
            "webhook": {"enabled": False},
            "events": {"finding_critical": True},
        })
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_config_persists(self, module_client: TestClient):
        module_client.put("/api/notifications/config", json={
            "telegram": {"enabled": False},
            "slack": {"enabled": True, "webhook_url": "https://hooks.slack.com/test"},
            "webhook": {},
            "events": {},
        })
        r = module_client.get("/api/notifications/config")
        assert r.status_code == 200
        data = r.json()
        assert data["slack"]["enabled"] is True


class TestTestNotification:
    def test_test_notification(self, module_client: TestClient):
        module_client.put("/api/notifications/config", json={
            "telegram": {},
            "slack": {},
            "webhook": {},
            "events": {},
        })
        r = module_client.post("/api/notifications/test")
        assert r.status_code == 200
        assert r.json()["ok"] is True


class TestTelegramChatId:
    def test_no_token_configured(self, module_client: TestClient):
        module_client.put("/api/notifications/config", json={
            "telegram": {},
            "slack": {},
            "webhook": {},
            "events": {},
        })
        r = module_client.get("/api/notifications/telegram/chat-id")
        assert r.status_code == 400
