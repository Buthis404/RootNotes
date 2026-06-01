"""Comprehensive tests for the host-activities API endpoints."""
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
    r = module_client.post("/api/projects", json={"name": "ActivitiesTest", "added": TS, "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]
    r = module_client.post("/api/hosts", json={
        "pid": _state["pid"], "ip": "10.2.2.2", "hostname": "act-host",
        "os": "Windows", "status": "alive",
    })
    assert r.status_code == 201
    _state["hid"] = r.json()["id"]
    yield
    module_client.post("/api/auth/logout")


class TestCreateHostActivity:
    def test_create_minimal(self, module_client: TestClient):
        r = module_client.post("/api/host-activities", json={
            "pid": _state["pid"], "host_id": _state["hid"],
            "title": "Port Scan", "activity_type": "recon", "ts": TS,
        })
        assert r.status_code == 201
        data = r.json()
        assert data["title"] == "Port Scan"
        assert data["activity_type"] == "recon"
        assert data["status"] == "done"
        _state["aid1"] = data["id"]

    def test_create_all_fields(self, module_client: TestClient):
        r = module_client.post("/api/host-activities", json={
            "pid": _state["pid"],
            "host_id": _state["hid"],
            "title": "Exploit Run",
            "activity_type": "exploit",
            "command": "run exploit.py --target 10.2.2.2",
            "summary": "Gained shell access",
            "output": "root@host:~#",
            "status": "done",
            "ts": TS,
        })
        assert r.status_code == 201
        data = r.json()
        assert data["command"] == "run exploit.py --target 10.2.2.2"
        assert data["summary"] == "Gained shell access"
        assert data["output"] == "root@host:~#"
        _state["aid2"] = data["id"]


class TestListHostActivities:
    def test_list_by_pid(self, module_client: TestClient):
        r = module_client.get("/api/host-activities", params={"pid": _state["pid"]})
        assert r.status_code == 200
        items = r.json()
        assert len(items) >= 2

    def test_list_filter_by_host_id(self, module_client: TestClient):
        r = module_client.get("/api/host-activities", params={"pid": _state["pid"], "host_id": _state["hid"]})
        assert r.status_code == 200
        for a in r.json():
            assert a["host_id"] == _state["hid"]

    def test_list_admin_no_pid(self, module_client: TestClient):
        r = module_client.get("/api/host-activities")
        assert r.status_code == 200
        assert isinstance(r.json(), list)


class TestUpdateHostActivity:
    def test_update_title(self, module_client: TestClient):
        r = module_client.patch(f"/api/host-activities/{_state['aid1']}", json={"title": "Updated Scan"})
        assert r.status_code == 200
        assert r.json()["title"] == "Updated Scan"

    def test_update_output(self, module_client: TestClient):
        r = module_client.patch(f"/api/host-activities/{_state['aid1']}", json={"output": "New output"})
        assert r.status_code == 200
        assert r.json()["output"] == "New output"

    def test_update_multiple_fields(self, module_client: TestClient):
        r = module_client.patch(f"/api/host-activities/{_state['aid2']}", json={
            "summary": "Updated summary", "status": "error",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["summary"] == "Updated summary"
        assert data["status"] == "error"

    def test_update_nonexistent(self, module_client: TestClient):
        r = module_client.patch("/api/host-activities/hanonexistent", json={"title": "x"})
        assert r.status_code == 404


class TestDeleteHostActivity:
    def test_delete(self, module_client: TestClient):
        r = module_client.post("/api/host-activities", json={
            "pid": _state["pid"], "host_id": _state["hid"],
            "title": "To Delete", "activity_type": "recon", "ts": TS,
        })
        aid = r.json()["id"]
        r = module_client.delete(f"/api/host-activities/{aid}")
        assert r.status_code == 204

    def test_delete_nonexistent(self, module_client: TestClient):
        r = module_client.delete("/api/host-activities/hanonexistent")
        assert r.status_code == 404
