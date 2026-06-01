"""Extended projects tests — CRUD, purge, update."""
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


class TestProjectCRUD:
    def test_create_project(self, module_client: TestClient):
        r = module_client.post("/api/projects", json={"name": "ExtTestProj", "added": "2025-01-01T00:00:00Z", "status": "active"})
        assert r.status_code == 201
        data = r.json()
        assert data["name"] == "ExtTestProj"
        _state["pid"] = data["id"]

    def test_list_projects(self, module_client: TestClient):
        r = module_client.get("/api/projects")
        assert r.status_code == 200
        projects = r.json()
        assert any(p["id"] == _state["pid"] for p in projects)

    def test_update_project(self, module_client: TestClient):
        r = module_client.patch(f"/api/projects/{_state['pid']}", json={"name": "ExtTestProjUpdated"})
        assert r.status_code == 200
        assert r.json()["name"] == "ExtTestProjUpdated"

    def test_update_project_ip(self, module_client: TestClient):
        r = module_client.patch(f"/api/projects/{_state['pid']}", json={"ip": "10.0.0.0/24"})
        assert r.status_code == 200

    def test_update_project_404(self, module_client: TestClient):
        r = module_client.patch("/api/projects/nonexistent", json={"name": "X"})
        assert r.status_code == 404


class TestProjectPurge:
    def test_purge_wrong_confirm(self, module_client: TestClient):
        r = module_client.post(f"/api/projects/{_state['pid']}/purge", json={"confirm": "wrong"})
        assert r.status_code == 400

    def test_purge_nonexistent(self, module_client: TestClient):
        r = module_client.post("/api/projects/nonexistent/purge", json={"confirm": "PURGE"})
        assert r.status_code == 404

    def test_delete_project(self, module_client: TestClient):
        r = module_client.delete(f"/api/projects/{_state['pid']}")
        assert r.status_code == 204

    def test_delete_nonexistent(self, module_client: TestClient):
        r = module_client.delete("/api/projects/nonexistent")
        assert r.status_code == 404
