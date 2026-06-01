"""Comprehensive API tests for the objectives router."""

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
        json={"name": "Objectives Test Proj", "added": "2025-01-01T00:00:00Z", "status": "active"},
    )
    assert r.status_code in (201, 409), f"project: {r.status_code} {r.text}"
    if r.status_code == 201:
        _state["pid"] = r.json()["id"]
    else:
        ps = module_client.get("/api/projects").json()
        _state["pid"] = next(p["id"] for p in ps if p["name"] == "Objectives Test Proj")
    yield


class TestObjectiveCRUD:
    def test_create(self, module_client):
        r = module_client.post(
            "/api/objectives",
            json={
                "pid": _state["pid"],
                "title": "Capture the flag",
                "description": "Find and submit the flag",
                "category": "flag",
                "points": 100,
                "status": "not_started",
            },
        )
        assert r.status_code in (200, 201), r.text
        data = r.json()
        assert data["title"] == "Capture the flag"
        assert data["category"] == "flag"
        assert data["points"] == 100
        assert data["status"] == "not_started"
        _state["oid"] = data["id"]

    def test_list(self, module_client):
        r = module_client.get("/api/objectives", params={"pid": _state["pid"]})
        assert r.status_code == 200
        ids = [o["id"] for o in r.json()]
        assert _state["oid"] in ids

    def test_update_title(self, module_client):
        r = module_client.patch(
            f"/api/objectives/{_state['oid']}",
            json={"title": "Updated Flag Objective"},
        )
        assert r.status_code == 200
        assert r.json()["title"] == "Updated Flag Objective"

    def test_update_description(self, module_client):
        r = module_client.patch(
            f"/api/objectives/{_state['oid']}",
            json={"description": "Updated description"},
        )
        assert r.status_code == 200
        assert r.json()["description"] == "Updated description"

    def test_update_points(self, module_client):
        r = module_client.patch(
            f"/api/objectives/{_state['oid']}",
            json={"points": 250},
        )
        assert r.status_code == 200
        assert r.json()["points"] == 250

    def test_update_status_to_in_progress(self, module_client):
        r = module_client.patch(
            f"/api/objectives/{_state['oid']}",
            json={"status": "in_progress"},
        )
        assert r.status_code == 200
        assert r.json()["status"] == "in_progress"

    def test_update_status_to_captured(self, module_client):
        r = module_client.patch(
            f"/api/objectives/{_state['oid']}",
            json={"status": "captured", "captured_by": "admin"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "captured"
        assert data["captured_by"] == "admin"

    def test_delete(self, module_client):
        r = module_client.delete(f"/api/objectives/{_state['oid']}")
        assert r.status_code == 200
        r = module_client.get("/api/objectives", params={"pid": _state["pid"]})
        ids = [o["id"] for o in r.json()]
        assert _state["oid"] not in ids


class TestObjectiveCategories:
    def test_create_flag_category(self, module_client):
        r = module_client.post(
            "/api/objectives",
            json={
                "pid": _state["pid"],
                "title": "Root flag",
                "category": "flag",
                "points": 50,
            },
        )
        assert r.status_code in (200, 201)
        assert r.json()["category"] == "flag"

    def test_create_domain_category(self, module_client):
        r = module_client.post(
            "/api/objectives",
            json={
                "pid": _state["pid"],
                "title": "Domain admin",
                "category": "domain",
                "points": 200,
            },
        )
        assert r.status_code in (200, 201)
        assert r.json()["category"] == "domain"

    def test_create_with_host_id(self, module_client):
        r_host = module_client.post(
            "/api/hosts",
            json={"pid": _state["pid"], "ip": "10.0.0.50"},
        )
        assert r_host.status_code == 201
        host_id = r_host.json()["id"]
        r = module_client.post(
            "/api/objectives",
            json={
                "pid": _state["pid"],
                "title": "Escalate on host",
                "category": "privilege_escalation",
                "host_id": host_id,
            },
        )
        assert r.status_code in (200, 201)
        assert r.json()["host_id"] == host_id


class TestObjectiveEdgeCases:
    def test_update_nonexistent_returns_404(self, module_client):
        r = module_client.patch("/api/objectives/nonexistent_obj", json={"title": "x"})
        assert r.status_code == 404

    def test_delete_nonexistent_returns_404(self, module_client):
        r = module_client.delete("/api/objectives/nonexistent_obj")
        assert r.status_code == 404
