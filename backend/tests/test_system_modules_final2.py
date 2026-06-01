import pytest
from fastapi.testclient import TestClient
from datetime import datetime, timezone

TS = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    r = module_client.post("/api/projects", json={"name": "SysModFinal2", "added": TS, "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]
    yield


class TestSystemModulesTemplates:
    def test_get_template(self, module_client: TestClient):
        r = module_client.get("/api/admin/modules/template")
        assert r.status_code == 200
        assert "BackendModule" in r.text

    def test_get_frontend_template(self, module_client: TestClient):
        r = module_client.get("/api/admin/modules/template/frontend")
        assert r.status_code == 200
        assert "moduleRegistry" in r.text


class TestSystemModulesValidate:
    def test_validate_good(self, module_client: TestClient):
        code = '''
from ..types import BackendModule

def sample_parser(content: str) -> list[dict]:
    return []

MODULE = BackendModule(
    name="test_mod", title="Test", version="1.0.0",
    description="desc", enabled=True, source="uploaded",
    editable=True, scan_parsers={"sample": sample_parser},
)
'''
        r = module_client.post("/api/admin/modules/validate",
                               json={"filename": "test_mod.py", "content": code})
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert data["module_name"] == "test_mod"

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

    def test_validate_sensitive_import_warning(self, module_client: TestClient):
        code = "import subprocess\nfrom ..types import BackendModule\nMODULE = BackendModule(name='x',title='x',version='1',description='',enabled=True)"
        r = module_client.post("/api/admin/modules/validate",
                               json={"filename": "test.py", "content": code})
        assert r.status_code == 200
        assert any("subprocess" in w for w in r.json()["warnings"])


class TestASTHelpers:
    def test_check_ast_import_node(self):
        from app.routers.system_modules import _check_ast_import_node
        import ast
        node = ast.parse("import subprocess").body[0]
        result = _check_ast_import_node(node)
        assert len(result) == 1

    def test_check_ast_import_from(self):
        from app.routers.system_modules import _check_ast_import_node
        import ast
        node = ast.parse("from socket import socket").body[0]
        result = _check_ast_import_node(node)
        assert len(result) == 1

    def test_check_ast_call_blocked(self):
        from app.routers.system_modules import _check_ast_call_node
        import ast
        node = ast.parse("eval('1')").body[0].value
        result = _check_ast_call_node(node)
        assert result is not None
        assert "eval" in result

    def test_check_ast_call_attribute_blocked(self):
        from app.routers.system_modules import _check_ast_call_node
        import ast
        node = ast.parse("builtins.eval('1')").body[0].value
        result = _check_ast_call_node(node)
        assert result is not None

    def test_scan_ast_tree(self):
        from app.routers.system_modules import _scan_ast_tree
        import ast
        tree = ast.parse("import subprocess\neval('1')")
        warnings, errors = _scan_ast_tree(tree)
        assert len(warnings) == 1
        assert len(errors) == 1


class TestValidateProxyHelpers:
    def test_validate_main_proxy_bad_type(self):
        from app.routers.system_modules import _validate_main_proxy, AttackerSSHTargetBody
        body = AttackerSSHTargetBody(proxy_type="invalid", name="t", host="h", username="u")
        with pytest.raises(Exception) as exc_info:
            _validate_main_proxy(body)
        assert exc_info.value.status_code == 400

    def test_validate_main_proxy_jump_no_host(self):
        from app.routers.system_modules import _validate_main_proxy, AttackerSSHTargetBody
        body = AttackerSSHTargetBody(proxy_type="jump", proxy_host="", name="t", host="h", username="u")
        with pytest.raises(Exception) as exc_info:
            _validate_main_proxy(body)
        assert exc_info.value.status_code == 400

    def test_validate_main_proxy_jump_no_user(self):
        from app.routers.system_modules import _validate_main_proxy, AttackerSSHTargetBody
        body = AttackerSSHTargetBody(proxy_type="jump", proxy_host="1.1.1.1", proxy_username="", name="t", host="h", username="u")
        with pytest.raises(Exception) as exc_info:
            _validate_main_proxy(body)
        assert exc_info.value.status_code == 400

    def test_validate_exec_proxy_bad_type(self):
        from app.routers.system_modules import _validate_exec_proxy, AttackerSSHTargetBody
        body = AttackerSSHTargetBody(exec_proxy_type="invalid", name="t", host="h", username="u")
        with pytest.raises(Exception) as exc_info:
            _validate_exec_proxy(body)
        assert exc_info.value.status_code == 400

    def test_validate_exec_proxy_no_host(self):
        from app.routers.system_modules import _validate_exec_proxy, AttackerSSHTargetBody
        body = AttackerSSHTargetBody(exec_proxy_type="socks5", exec_proxy_host="", name="t", host="h", username="u")
        with pytest.raises(Exception) as exc_info:
            _validate_exec_proxy(body)
        assert exc_info.value.status_code == 400

    def test_validate_attacker_target_no_roles(self):
        from app.routers.system_modules import _validate_attacker_target, AttackerSSHTargetBody
        from unittest.mock import patch
        body = AttackerSSHTargetBody(name="t", host="h", username="u", is_operator=False, runs_pivot=False)
        with patch("app.routers.system_modules._require_attacker_module_enabled"):
            with pytest.raises(Exception) as exc_info:
                _validate_attacker_target(body)
            assert exc_info.value.status_code == 400
