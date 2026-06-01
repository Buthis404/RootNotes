"""Comprehensive API tests for the scopes router."""

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
        json={"name": "Scopes Test Proj", "added": "2025-01-01T00:00:00Z", "status": "active"},
    )
    assert r.status_code in (201, 409), f"project: {r.status_code} {r.text}"
    if r.status_code == 201:
        _state["pid"] = r.json()["id"]
    else:
        ps = module_client.get("/api/projects").json()
        _state["pid"] = next(p["id"] for p in ps if p["name"] == "Scopes Test Proj")
    yield


class TestScopeCRUD:
    def test_create_cidr(self, module_client):
        r = module_client.post(
            "/api/scopes",
            json={
                "pid": _state["pid"],
                "value": "10.0.0.0/24",
                "scope_type": "cidr",
                "in_scope": True,
                "description": "Internal network",
            },
        )
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["value"] == "10.0.0.0/24"
        assert data["scope_type"] == "cidr"
        assert data["in_scope"] is True
        assert data["description"] == "Internal network"
        _state["sid"] = data["id"]

    def test_list(self, module_client):
        r = module_client.get("/api/scopes", params={"pid": _state["pid"]})
        assert r.status_code == 200
        ids = [s["id"] for s in r.json()]
        assert _state["sid"] in ids

    def test_update_description(self, module_client):
        r = module_client.patch(
            f"/api/scopes/{_state['sid']}",
            json={"description": "Updated scope desc"},
        )
        assert r.status_code == 200
        assert r.json()["description"] == "Updated scope desc"

    def test_update_in_scope(self, module_client):
        r = module_client.patch(
            f"/api/scopes/{_state['sid']}",
            json={"in_scope": False},
        )
        assert r.status_code == 200
        assert r.json()["in_scope"] is False

    def test_delete(self, module_client):
        r = module_client.delete(f"/api/scopes/{_state['sid']}")
        assert r.status_code == 204
        r = module_client.get("/api/scopes", params={"pid": _state["pid"]})
        ids = [s["id"] for s in r.json()]
        assert _state["sid"] not in ids


class TestScopeTypes:
    def test_create_ip_scope(self, module_client):
        r = module_client.post(
            "/api/scopes",
            json={
                "pid": _state["pid"],
                "value": "192.168.1.1",
                "scope_type": "ip",
                "in_scope": True,
            },
        )
        assert r.status_code == 201
        assert r.json()["value"] == "192.168.1.1"

    def test_create_domain_scope(self, module_client):
        r = module_client.post(
            "/api/scopes",
            json={
                "pid": _state["pid"],
                "value": "example.corp.local",
                "scope_type": "domain",
                "in_scope": True,
            },
        )
        assert r.status_code == 201
        assert r.json()["value"] == "example.corp.local"

    def test_create_exclusion_scope(self, module_client):
        r = module_client.post(
            "/api/scopes",
            json={
                "pid": _state["pid"],
                "value": "10.0.0.1/32",
                "scope_type": "cidr",
                "in_scope": False,
                "description": "Out of scope host",
            },
        )
        assert r.status_code == 201
        assert r.json()["in_scope"] is False


class TestScopeEntryFlag:
    def test_create_entry_scope(self, module_client):
        r = module_client.post(
            "/api/scopes",
            json={
                "pid": _state["pid"],
                "value": "172.16.0.0/16",
                "scope_type": "cidr",
                "is_entry": True,
            },
        )
        assert r.status_code == 201
        assert r.json()["is_entry"] is True
        _state["entry_sid"] = r.json()["id"]

    def test_new_entry_unsets_previous(self, module_client):
        r = module_client.post(
            "/api/scopes",
            json={
                "pid": _state["pid"],
                "value": "192.168.0.0/16",
                "scope_type": "cidr",
                "is_entry": True,
            },
        )
        assert r.status_code == 201
        new_id = r.json()["id"]
        r = module_client.get("/api/scopes", params={"pid": _state["pid"]})
        scopes = r.json()
        old_entry = next((s for s in scopes if s["id"] == _state["entry_sid"]), None)
        assert old_entry["is_entry"] is False
        new_entry = next((s for s in scopes if s["id"] == new_id), None)
        assert new_entry["is_entry"] is True


class TestScopeEdgeCases:
    def test_create_invalid_cidr(self, module_client):
        r = module_client.post(
            "/api/scopes",
            json={
                "pid": _state["pid"],
                "value": "not-a-cidr",
                "scope_type": "cidr",
            },
        )
        assert r.status_code in (422, 500)

    def test_create_empty_value(self, module_client):
        r = module_client.post(
            "/api/scopes",
            json={
                "pid": _state["pid"],
                "value": "",
                "scope_type": "cidr",
            },
        )
        assert r.status_code in (422, 500)

    def test_update_nonexistent_returns_404(self, module_client):
        r = module_client.patch("/api/scopes/nonexistent_sc", json={"description": "x"})
        assert r.status_code == 404

    def test_delete_nonexistent_returns_404(self, module_client):
        r = module_client.delete("/api/scopes/nonexistent_sc")
        assert r.status_code == 404
