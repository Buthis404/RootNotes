"""Comprehensive tests for the findings API endpoints."""
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
    r = module_client.post("/api/projects", json={"name": "FindingsTest", "added": TS, "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]
    r = module_client.post("/api/hosts", json={
        "pid": _state["pid"], "ip": "10.1.1.1", "hostname": "find-test-host",
        "os": "Linux", "status": "alive",
    })
    assert r.status_code == 201
    _state["hid"] = r.json()["id"]
    yield
    module_client.post("/api/auth/logout")


class TestCreateFinding:
    def test_create_minimal(self, module_client: TestClient):
        r = module_client.post("/api/findings", json={
            "pid": _state["pid"], "title": "Minimal Finding", "severity": "low", "ts": TS,
        })
        assert r.status_code == 201
        data = r.json()
        assert data["title"] == "Minimal Finding"
        assert data["severity"] == "low"
        assert data["status"] == "open"
        assert data["source"] == "manual"
        _state["fid_min"] = data["id"]

    def test_create_all_fields(self, module_client: TestClient):
        r = module_client.post("/api/findings", json={
            "pid": _state["pid"],
            "title": "Full Finding",
            "severity": "critical",
            "cvss": "9.8",
            "cve": "CVE-2024-1234",
            "description": "A critical vuln",
            "proof": "Proof text here",
            "recommendation": "Patch immediately",
            "status": "confirmed",
            "source": "nmap",
            "host_id": _state["hid"],
            "ts": TS,
        })
        assert r.status_code == 201
        data = r.json()
        assert data["severity"] == "critical"
        assert data["cvss"] == "9.8"
        assert data["cve"] == "CVE-2024-1234"
        assert data["description"] == "A critical vuln"
        assert data["proof"] == "Proof text here"
        assert data["recommendation"] == "Patch immediately"
        assert data["status"] == "confirmed"
        assert data["source"] == "nmap"
        assert data["host_id"] == _state["hid"]
        _state["fid_full"] = data["id"]

    def test_create_high_severity(self, module_client: TestClient):
        r = module_client.post("/api/findings", json={
            "pid": _state["pid"], "title": "High Finding", "severity": "high", "ts": TS,
        })
        assert r.status_code == 201
        _state["fid_high"] = r.json()["id"]


class TestListFindings:
    def test_list_by_pid(self, module_client: TestClient):
        r = module_client.get("/api/findings", params={"pid": _state["pid"]})
        assert r.status_code == 200
        items = r.json()
        assert len(items) >= 3
        assert "X-Total-Count" in r.headers

    def test_list_filter_by_status(self, module_client: TestClient):
        r = module_client.get("/api/findings", params={"pid": _state["pid"], "status": "confirmed"})
        assert r.status_code == 200
        for f in r.json():
            assert f["status"] == "confirmed"

    def test_list_filter_by_source(self, module_client: TestClient):
        r = module_client.get("/api/findings", params={"pid": _state["pid"], "source": "nmap"})
        assert r.status_code == 200
        for f in r.json():
            assert f["source"] == "nmap"

    def test_list_with_limit_and_offset(self, module_client: TestClient):
        r = module_client.get("/api/findings", params={"pid": _state["pid"], "limit": 1, "offset": 0})
        assert r.status_code == 200
        assert len(r.json()) <= 1

    def test_list_admin_no_pid(self, module_client: TestClient):
        r = module_client.get("/api/findings")
        assert r.status_code == 200
        assert isinstance(r.json(), list)


class TestUpdateFinding:
    def test_update_title(self, module_client: TestClient):
        r = module_client.patch(f"/api/findings/{_state['fid_min']}", json={"title": "Updated Title"})
        assert r.status_code == 200
        assert r.json()["title"] == "Updated Title"

    def test_update_severity(self, module_client: TestClient):
        r = module_client.patch(f"/api/findings/{_state['fid_min']}", json={"severity": "critical"})
        assert r.status_code == 200
        assert r.json()["severity"] == "critical"

    def test_update_status(self, module_client: TestClient):
        r = module_client.patch(f"/api/findings/{_state['fid_min']}", json={"status": "resolved"})
        assert r.status_code == 200
        assert r.json()["status"] == "resolved"

    def test_update_multiple_fields(self, module_client: TestClient):
        r = module_client.patch(f"/api/findings/{_state['fid_full']}", json={
            "cvss": "7.5", "description": "Updated desc", "recommendation": "New rec",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["cvss"] == "7.5"
        assert data["description"] == "Updated desc"
        assert data["recommendation"] == "New rec"

    def test_update_nonexistent(self, module_client: TestClient):
        r = module_client.patch("/api/findings/fnonexistent", json={"title": "x"})
        assert r.status_code == 404


class TestDeleteFinding:
    def test_delete(self, module_client: TestClient):
        r = module_client.post("/api/findings", json={
            "pid": _state["pid"], "title": "To Delete", "severity": "low", "ts": TS,
        })
        fid = r.json()["id"]
        r = module_client.delete(f"/api/findings/{fid}")
        assert r.status_code == 204

    def test_delete_nonexistent(self, module_client: TestClient):
        r = module_client.delete("/api/findings/fnonexistent")
        assert r.status_code == 404

    def test_deleted_not_in_list(self, module_client: TestClient):
        r = module_client.post("/api/findings", json={
            "pid": _state["pid"], "title": "Delete Verify", "severity": "low", "ts": TS,
        })
        fid = r.json()["id"]
        module_client.delete(f"/api/findings/{fid}")
        r = module_client.get("/api/findings", params={"pid": _state["pid"]})
        ids = [f["id"] for f in r.json()]
        assert fid not in ids
