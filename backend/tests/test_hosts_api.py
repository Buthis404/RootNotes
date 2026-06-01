"""Comprehensive API tests for the hosts router."""

import pytest
from fastapi.testclient import TestClient

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _setup(module_client):
    module_client.post("/api/auth/setup", json={"username": "admin", "password": "TestPass1234!"})
    r = module_client.post("/api/auth/login", json={"username": "admin", "password": "TestPass1234!"})
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text}"
    r = module_client.post(
        "/api/projects",
        json={"name": "Hosts Test Proj", "added": "2025-01-01T00:00:00Z", "status": "active"},
    )
    assert r.status_code in (201, 409), f"project: {r.status_code} {r.text}"
    if r.status_code == 201:
        _state["pid"] = r.json()["id"]
    else:
        ps = module_client.get("/api/projects").json()
        _state["pid"] = next(p["id"] for p in ps if p["name"] == "Hosts Test Proj")
    yield


class TestHostCRUD:
    def test_create(self, module_client):
        r = module_client.post(
            "/api/hosts",
            json={
                "pid": _state["pid"],
                "ip": "192.168.1.10",
                "hostname": "host-api-test",
                "os": "Linux",
                "status": "unknown",
            },
        )
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["ip"] == "192.168.1.10"
        assert data["hostname"] == "host-api-test"
        assert data["os"] == "Linux"
        assert "id" in data
        _state["hid"] = data["id"]

    def test_list_with_pid_filter(self, module_client):
        r = module_client.get("/api/hosts", params={"pid": _state["pid"]})
        assert r.status_code == 200
        items = r.json()
        ids = [h["id"] for h in items]
        assert _state["hid"] in ids

    def test_list_has_total_count_header(self, module_client):
        r = module_client.get("/api/hosts", params={"pid": _state["pid"]})
        assert r.status_code == 200
        assert "x-total-count" in r.headers

    def test_get_returns_expected_fields(self, module_client):
        r = module_client.get("/api/hosts", params={"pid": _state["pid"]})
        host = next(h for h in r.json() if h["id"] == _state["hid"])
        assert host["ip"] == "192.168.1.10"
        assert host["hostname"] == "host-api-test"
        assert host["status"] == "unknown"
        assert host["role"] == "unknown"

    def test_update_status(self, module_client):
        r = module_client.patch(
            f"/api/hosts/{_state['hid']}",
            json={"status": "pwned"},
        )
        assert r.status_code == 200
        assert r.json()["status"] == "pwned"

    def test_update_hostname_and_os(self, module_client):
        r = module_client.patch(
            f"/api/hosts/{_state['hid']}",
            json={"hostname": "renamed-host", "os": "Windows"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["hostname"] == "renamed-host"
        assert data["os"] == "Windows"

    def test_update_role(self, module_client):
        r = module_client.patch(
            f"/api/hosts/{_state['hid']}",
            json={"role": "server"},
        )
        assert r.status_code == 200
        assert r.json()["role"] == "server"

    def test_update_tags(self, module_client):
        r = module_client.patch(
            f"/api/hosts/{_state['hid']}",
            json={"tags": ["web", "critical"]},
        )
        assert r.status_code == 200
        assert r.json()["tags"] == ["web", "critical"]

    def test_delete(self, module_client):
        r = module_client.delete(f"/api/hosts/{_state['hid']}")
        assert r.status_code == 204
        r = module_client.get("/api/hosts", params={"pid": _state["pid"]})
        ids = [h["id"] for h in r.json()]
        assert _state["hid"] not in ids


class TestHostEdgeCases:
    def test_update_nonexistent_returns_404(self, module_client):
        r = module_client.patch("/api/hosts/nonexistent_hst", json={"status": "alive"})
        assert r.status_code == 404

    def test_delete_nonexistent_returns_404(self, module_client):
        r = module_client.delete("/api/hosts/nonexistent_hst")
        assert r.status_code == 404

    def test_create_with_invalid_status(self, module_client):
        r = module_client.post(
            "/api/hosts",
            json={
                "pid": _state["pid"],
                "ip": "192.168.1.99",
                "status": "invalid_status",
            },
        )
        assert r.status_code in (422, 500)

    def test_create_with_invalid_role(self, module_client):
        r = module_client.post(
            "/api/hosts",
            json={
                "pid": _state["pid"],
                "ip": "192.168.1.98",
                "role": "superadmin",
            },
        )
        assert r.status_code in (422, 500)

    def test_create_attacker_flag(self, module_client):
        r = module_client.post(
            "/api/hosts",
            json={
                "pid": _state["pid"],
                "ip": "10.10.10.1",
                "is_attacker": True,
            },
        )
        assert r.status_code == 201
        data = r.json()
        assert data["is_attacker"] is True
        assert data["status"] == "attacker"

    def test_second_host_same_project(self, module_client):
        r = module_client.post(
            "/api/hosts",
            json={
                "pid": _state["pid"],
                "ip": "192.168.1.20",
                "hostname": "host-api-test-2",
            },
        )
        assert r.status_code == 201
        r = module_client.get("/api/hosts", params={"pid": _state["pid"]})
        assert len(r.json()) >= 2
