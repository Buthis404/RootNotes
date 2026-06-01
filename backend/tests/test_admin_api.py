"""Comprehensive tests for the admin API endpoints."""
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
    yield
    module_client.post("/api/auth/logout")


class TestListUsers:
    def test_list_users(self, module_client: TestClient):
        r = module_client.get("/api/admin/users")
        assert r.status_code == 200
        items = r.json()
        assert isinstance(items, list)
        usernames = [u["username"] for u in items]
        assert ADMIN in usernames

    def test_list_users_schema(self, module_client: TestClient):
        r = module_client.get("/api/admin/users")
        items = r.json()
        for u in items:
            assert "id" in u
            assert "username" in u
            assert "role" in u
            assert "active" in u


class TestCreateUser:
    def test_create_user(self, module_client: TestClient):
        r = module_client.post("/api/admin/users", json={
            "username": "testuser1", "password": "TestPass1234!", "role": "user",
        })
        assert r.status_code == 201
        data = r.json()
        assert data["username"] == "testuser1"
        assert data["role"] == "user"
        assert data["active"] is True
        _state["uid1"] = data["id"]

    def test_create_user_with_display_name(self, module_client: TestClient):
        r = module_client.post("/api/admin/users", json={
            "username": "testuser2", "password": "TestPass1234!",
            "role": "operator", "display_name": "Test User 2",
        })
        assert r.status_code == 201
        data = r.json()
        assert data["display_name"] == "Test User 2"
        _state["uid2"] = data["id"]

    def test_create_duplicate_user(self, module_client: TestClient):
        r = module_client.post("/api/admin/users", json={
            "username": "testuser1", "password": "TestPass1234!", "role": "user",
        })
        assert r.status_code == 409


class TestUpdateUser:
    def test_update_display_name(self, module_client: TestClient):
        r = module_client.patch(f"/api/admin/users/{_state['uid1']}", json={
            "display_name": "Updated Name",
        })
        assert r.status_code == 200
        assert r.json()["display_name"] == "Updated Name"

    def test_update_role(self, module_client: TestClient):
        r = module_client.patch(f"/api/admin/users/{_state['uid1']}", json={"role": "admin"})
        assert r.status_code == 200
        assert r.json()["role"] == "admin"

    def test_update_password(self, module_client: TestClient):
        r = module_client.patch(f"/api/admin/users/{_state['uid1']}", json={
            "password": "NewPassword1234!",
        })
        assert r.status_code == 200

    def test_update_active(self, module_client: TestClient):
        r = module_client.patch(f"/api/admin/users/{_state['uid2']}", json={"active": False})
        assert r.status_code == 200
        assert r.json()["active"] is False

    def test_update_nonexistent(self, module_client: TestClient):
        r = module_client.patch("/api/admin/users/unonexistent", json={"display_name": "x"})
        assert r.status_code == 404

    def test_cannot_demote_self(self, module_client: TestClient):
        admin_id = None
        r = module_client.get("/api/admin/users")
        for u in r.json():
            if u["username"] == ADMIN:
                admin_id = u["id"]
                break
        assert admin_id is not None
        r = module_client.patch(f"/api/admin/users/{admin_id}", json={"role": "user"})
        assert r.status_code == 400

    def test_cannot_deactivate_self(self, module_client: TestClient):
        admin_id = None
        r = module_client.get("/api/admin/users")
        for u in r.json():
            if u["username"] == ADMIN:
                admin_id = u["id"]
                break
        r = module_client.patch(f"/api/admin/users/{admin_id}", json={"active": False})
        assert r.status_code == 400


class TestDeleteUser:
    def test_delete_user(self, module_client: TestClient):
        r = module_client.post("/api/admin/users", json={
            "username": "todelete", "password": "TestPass1234!", "role": "user",
        })
        uid = r.json()["id"]
        r = module_client.delete(f"/api/admin/users/{uid}")
        assert r.status_code == 204

    def test_delete_nonexistent(self, module_client: TestClient):
        r = module_client.delete("/api/admin/users/unonexistent")
        assert r.status_code == 404

    def test_cannot_delete_self(self, module_client: TestClient):
        admin_id = None
        r = module_client.get("/api/admin/users")
        for u in r.json():
            if u["username"] == ADMIN:
                admin_id = u["id"]
                break
        r = module_client.delete(f"/api/admin/users/{admin_id}")
        assert r.status_code == 400
