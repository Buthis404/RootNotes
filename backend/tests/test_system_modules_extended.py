"""Extended system modules tests — validation, attacker SSH targets."""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock, patch

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    yield


class TestModuleValidation:
    def test_validate_good_module(self, module_client: TestClient):
        content = '''from ..types import BackendModule

def sample_parser(content: str) -> list[dict]:
    return []

MODULE = BackendModule(
    name="test_mod", title="Test", version="1.0.0",
    description="desc", enabled=True, source="uploaded", editable=True,
    scan_parsers={"sample": sample_parser},
)
'''
        r = module_client.post(
            "/api/admin/modules/validate",
            json={"filename": "test_mod.py", "content": content},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True

    def test_validate_non_py_file(self, module_client: TestClient):
        r = module_client.post(
            "/api/admin/modules/validate",
            json={"filename": "test.txt", "content": "hello"},
        )
        assert r.status_code == 400

    def test_validate_empty_content(self, module_client: TestClient):
        r = module_client.post(
            "/api/admin/modules/validate",
            json={"filename": "test.py", "content": "  "},
        )
        assert r.status_code == 400

    def test_validate_syntax_error(self, module_client: TestClient):
        r = module_client.post(
            "/api/admin/modules/validate",
            json={"filename": "bad.py", "content": "def broken(\n"},
        )
        assert r.status_code == 400

    def test_validate_blocked_eval(self, module_client: TestClient):
        content = '''from ..types import BackendModule
MODULE = BackendModule(name="evil", title="Evil", version="1.0", description="", enabled=True)
x = eval("1+1")
'''
        r = module_client.post(
            "/api/admin/modules/validate",
            json={"filename": "evil.py", "content": content},
        )
        assert r.status_code == 400

    def test_validate_sensitive_import_warning(self, module_client: TestClient):
        content = '''from ..types import BackendModule
import subprocess
MODULE = BackendModule(name="mod", title="M", version="1.0", description="", enabled=True)
'''
        r = module_client.post(
            "/api/admin/modules/validate",
            json={"filename": "mod.py", "content": content},
        )
        assert r.status_code == 200
        data = r.json()
        assert len(data["warnings"]) > 0

    def test_validate_invalid_name(self, module_client: TestClient):
        r = module_client.post(
            "/api/admin/modules/validate",
            json={"filename": "has space.py", "content": "pass"},
        )
        assert r.status_code == 400


class TestModuleTemplate:
    def test_get_template(self, module_client: TestClient):
        r = module_client.get("/api/admin/modules/template")
        assert r.status_code == 200
        assert "BackendModule" in r.text

    def test_get_frontend_template(self, module_client: TestClient):
        r = module_client.get("/api/admin/modules/template/frontend")
        assert r.status_code == 200
        assert "moduleRegistry" in r.text


class TestModuleList:
    def test_list_modules(self, module_client: TestClient):
        r = module_client.get("/api/admin/modules")
        assert r.status_code == 200
        data = r.json()
        assert "modules" in data


class TestCreateModule:
    def test_create_custom(self, module_client: TestClient):
        with patch("app.routers.system_modules.create_custom_module") as mock_create:
            mock_create.return_value = {"name": "test_ext_mod", "title": "Test Ext", "version": "1.0"}
            r = module_client.post(
                "/api/admin/modules",
                json={"name": "test_ext_mod", "title": "Test Ext", "version": "1.0", "description": "test", "enabled": True},
            )
            assert r.status_code == 201

    def test_create_duplicate_fails(self, module_client: TestClient):
        with patch("app.routers.system_modules.create_custom_module", side_effect=ValueError("exists")):
            r = module_client.post(
                "/api/admin/modules",
                json={"name": "test_ext_mod", "title": "Dup", "version": "1.0"},
            )
            assert r.status_code == 400


class TestUpdateModule:
    def test_update_enabled(self, module_client: TestClient):
        with patch("app.routers.system_modules.update_module") as mock_update:
            mock_update.return_value = {"name": "test_ext_mod", "enabled": False}
            r = module_client.patch(
                "/api/admin/modules/test_ext_mod",
                json={"enabled": False},
            )
            assert r.status_code == 200

    def test_update_not_found(self, module_client: TestClient):
        r = module_client.patch(
            "/api/admin/modules/nonexistent_mod",
            json={"enabled": True},
        )
        assert r.status_code == 404


class TestDeleteModule:
    def test_delete_custom(self, module_client: TestClient):
        with patch("app.routers.system_modules.delete_custom_module"):
            r = module_client.delete("/api/admin/modules/test_ext_mod")
            assert r.status_code == 204

    def test_delete_not_found(self, module_client: TestClient):
        r = module_client.delete("/api/admin/modules/nonexistent_mod")
        assert r.status_code == 404


class TestAttackerSSHValidation:
    def test_create_target_validation_errors(self, module_client: TestClient):
        r = module_client.post(
            "/api/admin/modules/attacker-ssh/targets",
            json={"name": "", "host": "", "username": "", "port": 22, "password": "", "private_key": ""},
        )
        assert r.status_code in (400, 404)

    def test_invalid_proxy_type(self, module_client: TestClient):
        r = module_client.post(
            "/api/admin/modules/attacker-ssh/targets",
            json={
                "name": "t", "host": "10.0.0.1", "username": "root", "port": 22,
                "password": "pass", "proxy_type": "invalid_type",
            },
        )
        assert r.status_code in (400, 404)

    def test_invalid_exec_proxy_type(self, module_client: TestClient):
        r = module_client.post(
            "/api/admin/modules/attacker-ssh/targets",
            json={
                "name": "t", "host": "10.0.0.1", "username": "root", "port": 22,
                "password": "pass", "proxy_type": "none", "exec_proxy_type": "bad_type",
            },
        )
        assert r.status_code in (400, 404)


class TestAttackerSSHConfig:
    def test_get_config(self, module_client: TestClient):
        with patch("app.routers.system_modules.list_attacker_targets_safe") as mock_load:
            mock_load.return_value = []
            r = module_client.get("/api/admin/modules/attacker-ssh/config")
            assert r.status_code == 200
            assert "targets" in r.json()


class TestModuleSign:
    def test_sign_without_key(self, module_client: TestClient):
        content = 'from ..types import BackendModule\nMODULE = BackendModule(name="x", title="X", version="1.0", description="")\n'
        with patch("app.routers.system_modules.signing_enabled", return_value=False):
            r = module_client.post(
                "/api/admin/modules/sign",
                json={"filename": "x.py", "content": content},
            )
            assert r.status_code == 400
