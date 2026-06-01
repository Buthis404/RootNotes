"""Tests for scheduled playbooks router."""
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
    r = module_client.post("/api/projects", json={"name": "SchedPBTest", "added": "2025-01-01T00:00:00Z", "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]
    yield


class TestScheduledPlaybooksCRUD:
    def test_create_schedule(self, module_client: TestClient):
        r = module_client.post(
            "/api/scheduled-playbooks",
            json={
                "pid": _state["pid"],
                "playbook_id": "pb_test",
                "title": "Nightly Scan",
                "cron_expr": "0 2 * * *",
                "enabled": True,
                "body_json": {},
            },
        )
        assert r.status_code == 201
        data = r.json()
        assert data["title"] == "Nightly Scan"
        assert data["cron_expr"] == "0 2 * * *"
        _state["sid"] = data["id"]

    def test_create_invalid_cron(self, module_client: TestClient):
        r = module_client.post(
            "/api/scheduled-playbooks",
            json={
                "pid": _state["pid"],
                "playbook_id": "pb2",
                "title": "Bad",
                "cron_expr": "not valid cron",
                "enabled": True,
            },
        )
        assert r.status_code == 400

    def test_list_schedules(self, module_client: TestClient):
        r = module_client.get("/api/scheduled-playbooks", params={"pid": _state["pid"]})
        assert r.status_code == 200
        assert len(r.json()) >= 1

    def test_update_schedule(self, module_client: TestClient):
        r = module_client.patch(
            f"/api/scheduled-playbooks/{_state['sid']}",
            json={"title": "Updated Scan", "enabled": False},
        )
        assert r.status_code == 200
        assert r.json()["title"] == "Updated Scan"

    def test_update_schedule_invalid_cron(self, module_client: TestClient):
        r = module_client.patch(
            f"/api/scheduled-playbooks/{_state['sid']}",
            json={"cron_expr": "bad cron"},
        )
        assert r.status_code == 400

    def test_update_nonexistent(self, module_client: TestClient):
        r = module_client.patch(
            "/api/scheduled-playbooks/nonexistent",
            json={"title": "X"},
        )
        assert r.status_code == 404

    def test_delete_schedule(self, module_client: TestClient):
        r = module_client.delete(f"/api/scheduled-playbooks/{_state['sid']}")
        assert r.status_code == 204

    def test_delete_nonexistent(self, module_client: TestClient):
        r = module_client.delete("/api/scheduled-playbooks/nonexistent")
        assert r.status_code == 404
