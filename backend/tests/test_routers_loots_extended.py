"""Extended loots tests — CRUD and file upload."""
import io
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
    r = module_client.post("/api/projects", json={"name": "LootExtTest", "added": "2025-01-01T00:00:00Z", "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]
    yield


class TestLootCRUD:
    def test_create_loot(self, module_client: TestClient):
        r = module_client.post(
            "/api/loots",
            json={
                "pid": _state["pid"],
                "loot_type": "text",
                "value": "secret_value",
                "description": "test loot",
            },
        )
        assert r.status_code == 201
        data = r.json()
        assert data["description"] == "test loot"
        _state["lid"] = data["id"]

    def test_list_loots_by_pid(self, module_client: TestClient):
        r = module_client.get("/api/loots", params={"pid": _state["pid"]})
        assert r.status_code == 200
        assert len(r.json()) >= 1

    def test_update_loot(self, module_client: TestClient):
        r = module_client.patch(f"/api/loots/{_state['lid']}", json={"description": "updated loot"})
        assert r.status_code == 200
        assert r.json()["description"] == "updated loot"

    def test_update_nonexistent(self, module_client: TestClient):
        r = module_client.patch("/api/loots/nonexistent", json={"description": "x"})
        assert r.status_code == 404


class TestLootFileUpload:
    def test_upload_file(self, module_client: TestClient):
        r = module_client.post(
            f"/api/loots/{_state['lid']}/file",
            files={"file": ("test.txt", io.BytesIO(b"hello world"), "text/plain")},
        )
        assert r.status_code == 201
        data = r.json()
        assert data["filename"] == "test.txt"
        assert data["file_size"] == 11

    def test_upload_too_large(self, module_client: TestClient):
        big = io.BytesIO(b"x" * (50 * 1024 * 1024 + 1))
        r = module_client.post(
            f"/api/loots/{_state['lid']}/file",
            files={"file": ("big.bin", big, "application/octet-stream")},
        )
        assert r.status_code == 413

    def test_upload_nonexistent_loot(self, module_client: TestClient):
        r = module_client.post(
            "/api/loots/nonexistent/file",
            files={"file": ("test.txt", io.BytesIO(b"hi"), "text/plain")},
        )
        assert r.status_code == 404


class TestLootDelete:
    def test_delete_loot(self, module_client: TestClient):
        r = module_client.post(
            "/api/loots",
            json={"pid": _state["pid"], "loot_type": "text", "value": "to_delete"},
        )
        lid = r.json()["id"]
        r = module_client.delete(f"/api/loots/{lid}")
        assert r.status_code == 204

    def test_delete_nonexistent(self, module_client: TestClient):
        r = module_client.delete("/api/loots/nonexistent")
        assert r.status_code == 404
