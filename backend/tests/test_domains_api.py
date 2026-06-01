"""Comprehensive tests for the domains API endpoints."""
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
    r = module_client.post("/api/projects", json={"name": "DomainsTest", "added": TS, "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]
    yield
    module_client.post("/api/auth/logout")


class TestCreateDomain:
    def test_create_minimal(self, module_client: TestClient):
        r = module_client.post("/api/domains", json={
            "pid": _state["pid"], "name": "contoso.local",
        })
        assert r.status_code == 201
        data = r.json()
        assert data["name"] == "contoso.local"
        assert data["aliases"] == []
        assert data["notes"] == ""
        _state["did1"] = data["id"]

    def test_create_all_fields(self, module_client: TestClient):
        r = module_client.post("/api/domains", json={
            "pid": _state["pid"],
            "name": "fabrikam.com",
            "aliases": ["www.fabrikam.com", "mail.fabrikam.com"],
            "notes": "Primary domain",
        })
        assert r.status_code == 201
        data = r.json()
        assert data["name"] == "fabrikam.com"
        assert "www.fabrikam.com" in data["aliases"]
        assert data["notes"] == "Primary domain"
        _state["did2"] = data["id"]


class TestListDomains:
    def test_list_by_pid(self, module_client: TestClient):
        r = module_client.get("/api/domains", params={"pid": _state["pid"]})
        assert r.status_code == 200
        items = r.json()
        assert len(items) >= 2
        names = [d["name"] for d in items]
        assert "contoso.local" in names
        assert "fabrikam.com" in names


class TestUpdateDomain:
    def test_update_name(self, module_client: TestClient):
        r = module_client.patch(f"/api/domains/{_state['did1']}", json={"name": "contoso2.local"})
        assert r.status_code == 200
        assert r.json()["name"] == "contoso2.local"

    def test_update_aliases(self, module_client: TestClient):
        r = module_client.patch(f"/api/domains/{_state['did1']}", json={
            "aliases": ["dc1.contoso2.local"],
        })
        assert r.status_code == 200
        assert r.json()["aliases"] == ["dc1.contoso2.local"]

    def test_update_notes(self, module_client: TestClient):
        r = module_client.patch(f"/api/domains/{_state['did2']}", json={"notes": "Updated notes"})
        assert r.status_code == 200
        assert r.json()["notes"] == "Updated notes"

    def test_update_nonexistent(self, module_client: TestClient):
        r = module_client.patch("/api/domains/domnonexistent", json={"name": "x"})
        assert r.status_code == 404


class TestDeleteDomain:
    def test_delete(self, module_client: TestClient):
        r = module_client.post("/api/domains", json={
            "pid": _state["pid"], "name": "todelete.local",
        })
        did = r.json()["id"]
        r = module_client.delete(f"/api/domains/{did}")
        assert r.status_code == 204

    def test_delete_nonexistent(self, module_client: TestClient):
        r = module_client.delete("/api/domains/domnonexistent")
        assert r.status_code == 404

    def test_deleted_not_in_list(self, module_client: TestClient):
        r = module_client.post("/api/domains", json={
            "pid": _state["pid"], "name": "verify-delete.local",
        })
        did = r.json()["id"]
        module_client.delete(f"/api/domains/{did}")
        r = module_client.get("/api/domains", params={"pid": _state["pid"]})
        ids = [d["id"] for d in r.json()]
        assert did not in ids
