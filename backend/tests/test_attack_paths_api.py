"""Tests for attack paths and attack steps API endpoints."""
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
TS = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    r = module_client.post("/api/projects", json={"name": "AttackPathsTest", "added": TS, "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]
    r = module_client.post("/api/hosts", json={
        "pid": _state["pid"], "ip": "10.10.10.1", "hostname": "ap-host",
        "os": "Linux", "status": "alive",
    })
    assert r.status_code == 201
    _state["host_id"] = r.json()["id"]
    yield
    module_client.post("/api/auth/logout")


class TestListAttackPaths:
    def test_list_empty(self, module_client: TestClient):
        r = module_client.get("/api/attack-paths", params={"pid": _state["pid"]})
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_list_all_as_admin(self, module_client: TestClient):
        r = module_client.get("/api/attack-paths")
        assert r.status_code == 200


class TestCreateAttackPath:
    def test_create(self, module_client: TestClient):
        r = module_client.post("/api/attack-paths", json={
            "pid": _state["pid"],
            "name": "Initial Access Path",
            "description": "Phishing -> RCE -> Domain Admin",
        })
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["name"] == "Initial Access Path"
        assert data["pid"] == _state["pid"]
        assert "id" in data
        assert "ts" in data
        _state["ap_id"] = data["id"]

    def test_create_minimal(self, module_client: TestClient):
        r = module_client.post("/api/attack-paths", json={
            "pid": _state["pid"],
        })
        assert r.status_code == 200
        data = r.json()
        assert data["name"] == "Attack Path"
        assert data["description"] == ""
        _state["ap2_id"] = data["id"]


class TestUpdateAttackPath:
    def test_update(self, module_client: TestClient):
        r = module_client.patch(f"/api/attack-paths/{_state['ap_id']}", json={
            "name": "Updated Path",
            "description": "Updated desc",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["name"] == "Updated Path"
        assert data["description"] == "Updated desc"

    def test_update_not_found(self, module_client: TestClient):
        r = module_client.patch("/api/attack-paths/ap_nonexistent", json={"name": "X"})
        assert r.status_code == 404

    def test_partial_update(self, module_client: TestClient):
        r = module_client.patch(f"/api/attack-paths/{_state['ap_id']}", json={"name": "Only Name"})
        assert r.status_code == 200
        assert r.json()["name"] == "Only Name"


class TestDeleteAttackPath:
    def test_delete(self, module_client: TestClient):
        r = module_client.delete(f"/api/attack-paths/{_state['ap2_id']}")
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_delete_not_found(self, module_client: TestClient):
        r = module_client.delete("/api/attack-paths/ap_nonexistent")
        assert r.status_code == 404


class TestCreateAttackStep:
    def test_create(self, module_client: TestClient):
        r = module_client.post("/api/attack-steps", json={
            "path_id": _state["ap_id"],
            "pid": _state["pid"],
            "step_order": 1,
            "node_type": "host",
            "label": "Web Server",
            "technique": "T1190",
            "mitre_id": "T1190",
            "notes": "Exploit public-facing app",
        })
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["label"] == "Web Server"
        assert data["technique"] == "T1190"
        _state["step_id"] = data["id"]

    def test_create_with_host(self, module_client: TestClient):
        r = module_client.post("/api/attack-steps", json={
            "path_id": _state["ap_id"],
            "pid": _state["pid"],
            "host_id": _state["host_id"],
            "step_order": 2,
            "label": "DC",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["host_id"] == _state["host_id"]
        _state["step2_id"] = data["id"]


class TestListAttackSteps:
    def test_list_by_path(self, module_client: TestClient):
        r = module_client.get("/api/attack-steps", params={"path_id": _state["ap_id"]})
        assert r.status_code == 200
        data = r.json()
        assert len(data) >= 2

    def test_list_by_pid(self, module_client: TestClient):
        r = module_client.get("/api/attack-steps", params={"pid": _state["pid"]})
        assert r.status_code == 200
        assert len(r.json()) >= 2

    def test_list_all_as_admin(self, module_client: TestClient):
        r = module_client.get("/api/attack-steps")
        assert r.status_code == 200

    def test_list_nonexistent_path(self, module_client: TestClient):
        r = module_client.get("/api/attack-steps", params={"path_id": "ap_nonexistent"})
        assert r.status_code == 200
        assert r.json() == []


class TestUpdateAttackStep:
    def test_update(self, module_client: TestClient):
        r = module_client.patch(f"/api/attack-steps/{_state['step_id']}", json={
            "label": "Updated Web Server",
            "notes": "Updated notes",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["label"] == "Updated Web Server"
        assert data["notes"] == "Updated notes"

    def test_update_not_found(self, module_client: TestClient):
        r = module_client.patch("/api/attack-steps/as_nonexistent", json={"label": "X"})
        assert r.status_code == 404


class TestDeleteAttackStep:
    def test_delete(self, module_client: TestClient):
        r = module_client.delete(f"/api/attack-steps/{_state['step2_id']}")
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_delete_not_found(self, module_client: TestClient):
        r = module_client.delete("/api/attack-steps/as_nonexistent")
        assert r.status_code == 404


class TestListPathsWithData:
    def test_list_returns_created(self, module_client: TestClient):
        r = module_client.get("/api/attack-paths", params={"pid": _state["pid"]})
        assert r.status_code == 200
        data = r.json()
        assert any(p["id"] == _state["ap_id"] for p in data)
