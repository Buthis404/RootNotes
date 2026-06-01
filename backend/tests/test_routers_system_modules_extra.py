"""Extended tests for system_modules — validation and proxy helpers."""
import pytest
from fastapi.testclient import TestClient

from app.plugins.loader import _register_builtin_modules

_register_builtin_modules()

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _setup(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    yield


class TestModuleTemplates:
    def test_frontend_template(self, module_client: TestClient):
        r = module_client.get("/api/admin/modules/template/frontend")
        assert r.status_code == 200
        assert "moduleRegistry" in r.text

    def test_module_template(self, module_client: TestClient):
        r = module_client.get("/api/admin/modules/template")
        assert r.status_code == 200
        assert "BackendModule" in r.text


class TestModuleValidation:
    def test_valid_module(self, module_client: TestClient):
        r = module_client.post("/api/admin/modules/validate", json={
            "filename": "test_mod.py",
            "content": "from ..types import BackendModule\nMODULE = BackendModule(name='test')",
        })
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_non_py_file(self, module_client: TestClient):
        r = module_client.post("/api/admin/modules/validate", json={
            "filename": "test.txt",
            "content": "print('hi')",
        })
        assert r.status_code == 400

    def test_invalid_name(self, module_client: TestClient):
        r = module_client.post("/api/admin/modules/validate", json={
            "filename": "bad name!.py",
            "content": "from ..types import BackendModule\nMODULE = BackendModule(name='test')",
        })
        assert r.status_code == 400

    def test_empty_content(self, module_client: TestClient):
        r = module_client.post("/api/admin/modules/validate", json={
            "filename": "test.py",
            "content": "",
        })
        assert r.status_code == 400

    def test_syntax_error(self, module_client: TestClient):
        r = module_client.post("/api/admin/modules/validate", json={
            "filename": "test.py",
            "content": "def (",
        })
        assert r.status_code == 400

    def test_blocked_eval(self, module_client: TestClient):
        r = module_client.post("/api/admin/modules/validate", json={
            "filename": "test.py",
            "content": "from ..types import BackendModule\neval('1')\nMODULE = BackendModule(name='t')",
        })
        assert r.status_code == 400

    def test_sensitive_import_warning(self, module_client: TestClient):
        content = "import subprocess\nfrom ..types import BackendModule\nMODULE = BackendModule(name='t')"
        r = module_client.post("/api/admin/modules/validate", json={
            "filename": "test.py", "content": content,
        })
        assert r.status_code == 200
        assert any("subprocess" in w for w in r.json()["warnings"])


class TestAttackerTargetValidation:
    def test_invalid_proxy_type(self, module_client: TestClient):
        r = module_client.post("/api/admin/modules/attacker-ssh/targets", json={
            "name": "t", "host": "1.1.1.1", "port": 22, "username": "u",
            "password": "p", "proxy_type": "invalid_proxy",
        })
        assert r.status_code == 400

    def test_missing_name(self, module_client: TestClient):
        r = module_client.post("/api/admin/modules/attacker-ssh/targets", json={
            "name": "", "host": "1.1.1.1", "port": 22, "username": "u",
            "password": "p",
        })
        assert r.status_code == 400

    def test_invalid_port(self, module_client: TestClient):
        r = module_client.post("/api/admin/modules/attacker-ssh/targets", json={
            "name": "t", "host": "1.1.1.1", "port": 99999, "username": "u",
            "password": "p",
        })
        assert r.status_code == 400

    def test_no_password_or_key(self, module_client: TestClient):
        r = module_client.post("/api/admin/modules/attacker-ssh/targets", json={
            "name": "t", "host": "1.1.1.1", "port": 22, "username": "u",
            "password": "", "private_key": "",
        })
        assert r.status_code == 400

    def test_proxy_host_required(self, module_client: TestClient):
        r = module_client.post("/api/admin/modules/attacker-ssh/targets", json={
            "name": "t", "host": "1.1.1.1", "port": 22, "username": "u",
            "password": "p", "proxy_type": "jump", "proxy_host": "",
            "proxy_port": 22,
        })
        assert r.status_code == 400

    def test_exec_proxy_invalid_type(self, module_client: TestClient):
        r = module_client.post("/api/admin/modules/attacker-ssh/targets", json={
            "name": "t", "host": "1.1.1.1", "port": 22, "username": "u",
            "password": "p", "exec_proxy_type": "bad",
        })
        assert r.status_code == 400

    def test_neither_operator_nor_pivot(self, module_client: TestClient):
        r = module_client.post("/api/admin/modules/attacker-ssh/targets", json={
            "name": "t", "host": "1.1.1.1", "port": 22, "username": "u",
            "password": "p", "is_operator": False, "runs_pivot": False,
        })
        assert r.status_code == 400


class TestModuleCRUD:
    def test_list_modules(self, module_client: TestClient):
        r = module_client.get("/api/admin/modules")
        assert r.status_code == 200
        assert "modules" in r.json()

    def test_create_duplicate_module(self, module_client: TestClient):
        module_client.post("/api/admin/modules", json={
            "name": "test_dup_mod", "title": "Dup", "version": "1.0",
        })
        r = module_client.post("/api/admin/modules", json={
            "name": "test_dup_mod", "title": "Dup2", "version": "1.0",
        })
        assert r.status_code == 500

    def test_update_nonexistent(self, module_client: TestClient):
        r = module_client.patch("/api/admin/modules/nonexistent_mod", json={
            "enabled": True,
        })
        assert r.status_code == 404

    def test_delete_nonexistent(self, module_client: TestClient):
        r = module_client.delete("/api/admin/modules/nonexistent_mod_xyz")
        assert r.status_code == 404
