import pytest
from fastapi.testclient import TestClient

TS = "2024-01-01T00:00:00Z"
ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    yield


class TestSystemModulesAPI:
    def test_list_modules(self, module_client: TestClient):
        r = module_client.get("/api/admin/modules")
        assert r.status_code == 200

    def test_get_template(self, module_client: TestClient):
        r = module_client.get("/api/admin/modules/template")
        assert r.status_code == 200
        assert "BackendModule" in r.text

    def test_get_frontend_template(self, module_client: TestClient):
        r = module_client.get("/api/admin/modules/template/frontend")
        assert r.status_code == 200
        assert "moduleRegistry" in r.text

    def test_validate_good(self, module_client: TestClient):
        code = 'from ..types import BackendModule\nMODULE = BackendModule(name="test_mod", title="Test", version="1.0", description="", enabled=True)\n'
        r = module_client.post("/api/admin/modules/validate",
                               json={"filename": "test_mod.py", "content": code})
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_validate_non_py(self, module_client: TestClient):
        r = module_client.post("/api/admin/modules/validate",
                               json={"filename": "test.txt", "content": "x"})
        assert r.status_code == 400

    def test_validate_bad_name(self, module_client: TestClient):
        r = module_client.post("/api/admin/modules/validate",
                               json={"filename": "bad module!.py", "content": "x"})
        assert r.status_code == 400

    def test_validate_empty(self, module_client: TestClient):
        r = module_client.post("/api/admin/modules/validate",
                               json={"filename": "test.py", "content": ""})
        assert r.status_code == 400

    def test_validate_syntax_error(self, module_client: TestClient):
        r = module_client.post("/api/admin/modules/validate",
                               json={"filename": "test.py", "content": "def ("})
        assert r.status_code == 400

    def test_validate_blocked_call(self, module_client: TestClient):
        r = module_client.post("/api/admin/modules/validate",
                               json={"filename": "test.py",
                                     "content": "from ..types import BackendModule\nMODULE = BackendModule(name='x',title='x',version='1',description='',enabled=True)\nx = eval('1')"})
        assert r.status_code == 400
