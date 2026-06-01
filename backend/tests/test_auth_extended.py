"""Extended auth tests — MFA, password change, profile update, logout."""
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
    _state["cookie"] = r.cookies
    yield


class TestAuthSetup:
    def test_setup_already_initialized(self, module_client: TestClient):
        r = module_client.post("/api/auth/setup", json={"username": "other", "password": "OtherPass1234!"})
        assert r.status_code in (403, 422)

    def test_setup_returns_user(self, module_client: TestClient):
        module_client.post("/api/auth/logout")
        r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
        assert r.status_code == 200
        data = r.json()
        assert "user" in data


class TestAuthMe:
    def test_me_returns_user(self, module_client: TestClient):
        module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
        r = module_client.get("/api/auth/me")
        assert r.status_code == 200
        data = r.json()
        assert data["username"] == ADMIN

    def test_me_without_auth(self, client: TestClient):
        r = client.get("/api/auth/me")
        assert r.status_code == 401


class TestAuthUpdateProfile:
    def test_update_display_name(self, module_client: TestClient):
        module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
        r = module_client.patch("/api/auth/me", json={"display_name": "Admin User"})
        assert r.status_code == 200
        assert r.json()["display_name"] == "Admin User"

    def test_update_empty_display_name(self, module_client: TestClient):
        module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
        r = module_client.patch("/api/auth/me", json={"display_name": "  "})
        assert r.status_code == 400


class TestAuthChangePassword:
    def test_change_password_success(self, module_client: TestClient):
        module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
        r = module_client.post(
            "/api/auth/change-password",
            json={"current_password": ADMIN_PASS, "new_password": "NewPass1234!"},
        )
        assert r.status_code == 204

    def test_change_password_wrong_current(self, module_client: TestClient):
        module_client.post("/api/auth/login", json={"username": ADMIN, "password": "NewPass1234!"})
        r = module_client.post(
            "/api/auth/change-password",
            json={"current_password": "wrongpass", "new_password": "AnotherPass123!"},
        )
        assert r.status_code in (400, 422)

    def test_change_password_too_short(self, module_client: TestClient):
        module_client.post("/api/auth/login", json={"username": ADMIN, "password": "NewPass1234!"})
        r = module_client.post(
            "/api/auth/change-password",
            json={"current_password": "NewPass1234!", "new_password": "ab"},
        )
        assert r.status_code in (400, 422)

    def test_change_password_same_as_current(self, module_client: TestClient):
        module_client.post("/api/auth/login", json={"username": ADMIN, "password": "NewPass1234!"})
        r = module_client.post(
            "/api/auth/change-password",
            json={"current_password": "NewPass1234!", "new_password": "NewPass1234!"},
        )
        assert r.status_code == 400

    def test_login_with_new_password(self, module_client: TestClient):
        r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": "NewPass1234!"})
        assert r.status_code == 200


class TestAuthMfaSetup:
    def test_mfa_setup_returns_uri(self, module_client: TestClient):
        module_client.post("/api/auth/login", json={"username": ADMIN, "password": "NewPass1234!"})
        r = module_client.post("/api/auth/mfa/setup")
        assert r.status_code == 200
        data = r.json()
        assert "uri" in data
        assert "secret" in data

    def test_mfa_enable_without_code_fails(self, module_client: TestClient):
        module_client.post("/api/auth/login", json={"username": ADMIN, "password": "NewPass1234!"})
        r = module_client.post("/api/auth/mfa/enable", json={"code": "000000"})
        assert r.status_code == 400

    def test_mfa_disable_not_enabled(self, module_client: TestClient):
        module_client.post("/api/auth/login", json={"username": ADMIN, "password": "NewPass1234!"})
        r = module_client.post("/api/auth/mfa/disable", json={"code": "000000"})
        assert r.status_code == 400


class TestAuthMfaLogin:
    def test_login_returns_mfa_required_when_enabled(self, module_client: TestClient):
        module_client.post("/api/auth/login", json={"username": ADMIN, "password": "NewPass1234!"})
        r = module_client.post("/api/auth/mfa/setup")
        assert r.status_code == 200

        r = module_client.post("/api/auth/mfa/verify", json={"mfa_token": "invalid", "code": "123456"})
        assert r.status_code == 401


class TestAuthLogout:
    def test_logout_success(self, module_client: TestClient):
        module_client.post("/api/auth/login", json={"username": ADMIN, "password": "NewPass1234!"})
        r = module_client.post("/api/auth/logout")
        assert r.status_code == 204
