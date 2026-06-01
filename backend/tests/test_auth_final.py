import pytest


@pytest.fixture(scope="module", autouse=True)
def _setup(module_client):
    module_client.post("/api/auth/setup", json={"username": "admin", "password": "TestPass1234!"})
    r = module_client.post("/api/auth/login", json={"username": "admin", "password": "TestPass1234!"})
    assert r.status_code == 200, f"login: {r.status_code} {r.text}"
    r = module_client.post("/api/projects", json={"name": "AuthFinalTest", "added": "2025-01-01T00:00:00Z", "status": "active"})
    if r.status_code == 201:
        _state["pid"] = r.json()["id"]
    else:
        ps = module_client.get("/api/projects").json()
        _state["pid"] = next(p["id"] for p in ps if p["name"] == "AuthFinalTest")
    yield


_state = {}


class TestAuthMe:
    def test_me(self, module_client):
        r = module_client.get("/api/auth/me")
        assert r.status_code == 200
        data = r.json()
        assert data["username"] == "admin"

    def test_update_me(self, module_client):
        r = module_client.patch("/api/auth/me", json={"display_name": "Admin User"})
        assert r.status_code == 200
        assert r.json()["display_name"] == "Admin User"

    def test_update_me_empty(self, module_client):
        r = module_client.patch("/api/auth/me", json={"display_name": ""})
        assert r.status_code == 400


class TestAuthChangePassword:
    def test_wrong_current(self, module_client):
        r = module_client.post("/api/auth/change-password", json={"current_password": "wrong", "new_password": "NewPass1234!"})
        assert r.status_code == 400

    def test_same_password(self, module_client):
        r = module_client.post("/api/auth/change-password", json={"current_password": "TestPass1234!", "new_password": "TestPass1234!"})
        assert r.status_code == 400

    def test_too_short(self, module_client):
        r = module_client.post("/api/auth/change-password", json={"current_password": "TestPass1234!", "new_password": "ab"})
        assert r.status_code in (400, 422)


class TestAuthLogout:
    def test_logout_and_relogin(self, module_client):
        r = module_client.post("/api/auth/logout")
        assert r.status_code == 204
        r = module_client.post("/api/auth/login", json={"username": "admin", "password": "TestPass1234!"})
        assert r.status_code == 200


class TestAuthStatus:
    def test_status(self, module_client):
        r = module_client.get("/api/auth/status")
        assert r.status_code == 200
        assert r.json()["initialized"] is True
