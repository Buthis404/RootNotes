"""Consolidated tests for test_system_modules (merged variant files)."""

# ════════ from test_system_modules_api.py ════════
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


# ════════ from test_system_modules_extended.py ════════
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


# ════════ from test_system_modules_final.py ════════
import pytest
from unittest.mock import MagicMock, patch

from app.routers.system_modules import (
    _check_ast_import_node,
    _check_ast_call_node,
    _scan_ast_tree,
    _validate_module_source,
    _validate_main_proxy,
    _validate_exec_proxy,
    _validate_attacker_target,
    _resolve_next_credentials,
    MODULE_TEMPLATE,
    FRONTEND_MODULE_TEMPLATE,
)
import ast


class TestCheckAstImportNode_final:
    def test_sensitive_import(self):
        node = ast.parse("import subprocess").body[0]
        warnings = _check_ast_import_node(node)
        assert len(warnings) == 1
        assert "subprocess" in warnings[0]

    def test_normal_import(self):
        node = ast.parse("import os").body[0]
        warnings = _check_ast_import_node(node)
        assert len(warnings) == 0

    def test_from_import(self):
        node = ast.parse("from socket import socket").body[0]
        warnings = _check_ast_import_node(node)
        assert len(warnings) == 1


class TestCheckAstCallNode_final:
    def test_eval(self):
        tree = ast.parse("eval('1+1')")
        node = tree.body[0].value
        result = _check_ast_call_node(node)
        assert result is not None
        assert "eval" in result

    def test_exec(self):
        tree = ast.parse("exec('code')")
        node = tree.body[0].value
        result = _check_ast_call_node(node)
        assert "exec" in result

    def test_normal_call(self):
        tree = ast.parse("print('hello')")
        node = tree.body[0].value
        result = _check_ast_call_node(node)
        assert result is None


class TestScanAstTree_final:
    def test_clean(self):
        tree = ast.parse("x = 1\ny = 2")
        warnings, errors = _scan_ast_tree(tree)
        assert len(warnings) == 0
        assert len(errors) == 0

    def test_with_sensitive_import(self):
        tree = ast.parse("import subprocess")
        warnings, errors = _scan_ast_tree(tree)
        assert len(warnings) > 0

    def test_with_blocked_call(self):
        tree = ast.parse("eval('x')")
        warnings, errors = _scan_ast_tree(tree)
        assert len(errors) > 0


class TestValidateModuleSource_final:
    def test_not_py(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            _validate_module_source("test.txt", "code")

    def test_invalid_name(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            _validate_module_source("my module!.py", "code")

    def test_empty(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            _validate_module_source("test.py", "  ")

    def test_syntax_error(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            _validate_module_source("test.py", "def foo(")

    def test_blocked_call(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            _validate_module_source("test.py", "eval('x')")

    def test_valid(self):
        name, warnings = _validate_module_source("test.py", "x = 1")
        assert name == "test"


class TestValidateMainProxy_final:
    def test_none(self):
        body = MagicMock()
        body.proxy_type = "none"
        _validate_main_proxy(body)

    def test_invalid_type(self):
        from fastapi import HTTPException
        body = MagicMock()
        body.proxy_type = "invalid"
        with pytest.raises(HTTPException):
            _validate_main_proxy(body)

    def test_no_host(self):
        from fastapi import HTTPException
        body = MagicMock()
        body.proxy_type = "socks5"
        body.proxy_host = ""
        body.proxy_port = 1080
        with pytest.raises(HTTPException):
            _validate_main_proxy(body)

    def test_jump_no_user(self):
        from fastapi import HTTPException
        body = MagicMock()
        body.proxy_type = "jump"
        body.proxy_host = "1.2.3.4"
        body.proxy_port = 22
        body.proxy_username = ""
        body.proxy_password = ""
        body.proxy_private_key = ""
        with pytest.raises(HTTPException):
            _validate_main_proxy(body)


class TestValidateExecProxy_final:
    def test_none(self):
        body = MagicMock()
        body.exec_proxy_type = "none"
        _validate_exec_proxy(body)

    def test_invalid_type(self):
        from fastapi import HTTPException
        body = MagicMock()
        body.exec_proxy_type = "invalid"
        with pytest.raises(HTTPException):
            _validate_exec_proxy(body)

    def test_no_host(self):
        from fastapi import HTTPException
        body = MagicMock()
        body.exec_proxy_type = "socks5"
        body.exec_proxy_host = ""
        body.exec_proxy_port = 1080
        with pytest.raises(HTTPException):
            _validate_exec_proxy(body)


class TestValidateAttackerTarget_final:
    def test_disabled_module(self):
        from fastapi import HTTPException
        body = MagicMock()
        with patch("app.routers.system_modules._require_attacker_module_enabled", side_effect=HTTPException(404)):
            with pytest.raises(HTTPException):
                _validate_attacker_target(body)

    def test_not_operator_and_not_pivot(self):
        from fastapi import HTTPException
        body = MagicMock()
        body.name = "t"
        body.host = "h"
        body.username = "u"
        body.port = 22
        body.proxy_type = "none"
        body.exec_proxy_type = "none"
        body.is_operator = False
        body.runs_pivot = False
        with patch("app.routers.system_modules._require_attacker_module_enabled"):
            with pytest.raises(HTTPException):
                _validate_attacker_target(body)


class TestResolveNextCredentials_final:
    def test_with_new_password(self):
        body = MagicMock()
        body.password = "new_pass"
        body.private_key = "  "
        body.proxy_password = "pp"
        body.proxy_private_key = "pk"
        body.exec_proxy_password = "ep"
        result = _resolve_next_credentials(body, {"password": "old_pass", "private_key": "old_key", "proxy_password": "old_pp", "proxy_private_key": "old_pk", "exec_proxy_password": "old_ep"})
        assert result["password"] == "new_pass"
        assert result["private_key"] == "old_key"

    def test_fallback_password(self):
        body = MagicMock()
        body.password = ""
        body.private_key = ""
        body.proxy_password = ""
        body.proxy_private_key = ""
        body.exec_proxy_password = ""
        result = _resolve_next_credentials(body, {"password": "old", "private_key": "", "proxy_password": "", "proxy_private_key": "", "exec_proxy_password": ""})
        assert result["password"] == "old"


class TestTemplates_final:
    def test_module_template(self):
        assert "BackendModule" in MODULE_TEMPLATE

    def test_frontend_template(self):
        assert "moduleRegistry" in FRONTEND_MODULE_TEMPLATE


# ════════ from test_system_modules_final2.py ════════
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


# ════════ from test_system_modules_v3.py ════════
import pytest
from unittest.mock import MagicMock, patch
from fastapi import HTTPException

from app.routers.system_modules import (
    _check_ast_import_node,
    _check_ast_call_node,
    _scan_ast_tree,
    _validate_module_source,
    _validate_main_proxy,
    _validate_exec_proxy,
    _validate_attacker_target,
    _resolve_next_credentials,
    MODULE_TEMPLATE,
    FRONTEND_MODULE_TEMPLATE,
    MODULE_NAME_RE,
)
import ast


class TestCheckAstImportNode_v3:
    def test_normal_import(self):
        node = ast.parse("import os").body[0]
        assert _check_ast_import_node(node) == []

    def test_sensitive_import(self):
        node = ast.parse("import subprocess").body[0]
        r = _check_ast_import_node(node)
        assert len(r) == 1
        assert "subprocess" in r[0]

    def test_from_import(self):
        node = ast.parse("from socket import socket").body[0]
        r = _check_ast_import_node(node)
        assert len(r) == 1
        assert "socket" in r[0]

    def test_multiple_imports(self):
        node = ast.parse("import subprocess, socket").body[0]
        r = _check_ast_import_node(node)
        assert len(r) == 2


class TestCheckAstCallNode_v3:
    def test_eval(self):
        tree = ast.parse("eval('x')")
        call = [n for n in ast.walk(tree) if isinstance(n, ast.Call)][0]
        r = _check_ast_call_node(call)
        assert r is not None
        assert "eval" in r

    def test_exec(self):
        tree = ast.parse("exec('x')")
        call = [n for n in ast.walk(tree) if isinstance(n, ast.Call)][0]
        r = _check_ast_call_node(call)
        assert "exec" in r

    def test_import(self):
        tree = ast.parse("__import__('os')")
        call = [n for n in ast.walk(tree) if isinstance(n, ast.Call)][0]
        r = _check_ast_call_node(call)
        assert "__import__" in r

    def test_safe_call(self):
        tree = ast.parse("print('hello')")
        call = [n for n in ast.walk(tree) if isinstance(n, ast.Call)][0]
        assert _check_ast_call_node(call) is None

    def test_attr_eval(self):
        tree = ast.parse("builtins.eval('x')")
        call = [n for n in ast.walk(tree) if isinstance(n, ast.Call)][0]
        r = _check_ast_call_node(call)
        assert "eval" in r


class TestScanAstTree_v3:
    def test_clean(self):
        tree = ast.parse("x = 1\ny = 2")
        w, e = _scan_ast_tree(tree)
        assert w == []
        assert e == []

    def test_with_warnings_and_errors(self):
        tree = ast.parse("import subprocess\neval('x')")
        w, e = _scan_ast_tree(tree)
        assert len(w) == 1
        assert len(e) == 1


class TestValidateModuleSource_v3:
    def test_valid(self):
        code = 'from ..types import BackendModule\nMODULE = BackendModule(name="test")\n'
        name, warnings = _validate_module_source("test.py", code)
        assert name == "test"

    def test_non_py(self):
        with pytest.raises(HTTPException) as exc_info:
            _validate_module_source("test.js", "code")
        assert exc_info.value.status_code == 400

    def test_bad_name(self):
        with pytest.raises(HTTPException):
            _validate_module_source("bad module!.py", "code")

    def test_empty(self):
        with pytest.raises(HTTPException) as exc_info:
            _validate_module_source("test.py", "  ")
        assert exc_info.value.status_code == 400

    def test_syntax_error(self):
        with pytest.raises(HTTPException) as exc_info:
            _validate_module_source("test.py", "def (")
        assert exc_info.value.status_code == 400

    def test_blocked_call(self):
        code = 'eval("1+1")\nfrom ..types import BackendModule\nMODULE = BackendModule(name="t")\n'
        with pytest.raises(HTTPException) as exc_info:
            _validate_module_source("test.py", code)
        assert "rejected" in str(exc_info.value.detail).lower()

    def test_missing_markers(self):
        name, warnings = _validate_module_source("test.py", "x = 1\n")
        assert len(warnings) >= 1


class TestValidateMainProxy_v3:
    def test_none(self):
        body = MagicMock()
        body.proxy_type = "none"
        _validate_main_proxy(body)

    def test_invalid_type(self):
        body = MagicMock()
        body.proxy_type = "http"
        with pytest.raises(HTTPException) as exc_info:
            _validate_main_proxy(body)
        assert exc_info.value.status_code == 400

    def test_socks5_no_host(self):
        body = MagicMock()
        body.proxy_type = "socks5"
        body.proxy_host = ""
        body.proxy_port = 1080
        with pytest.raises(HTTPException):
            _validate_main_proxy(body)

    def test_socks5_invalid_port(self):
        body = MagicMock()
        body.proxy_type = "socks5"
        body.proxy_host = "10.0.0.1"
        body.proxy_port = 0
        with pytest.raises(HTTPException):
            _validate_main_proxy(body)

    def test_jump_no_username(self):
        body = MagicMock()
        body.proxy_type = "jump"
        body.proxy_host = "10.0.0.1"
        body.proxy_port = 22
        body.proxy_username = ""
        body.proxy_password = ""
        body.proxy_private_key = ""
        with pytest.raises(HTTPException):
            _validate_main_proxy(body)

    def test_jump_no_auth(self):
        body = MagicMock()
        body.proxy_type = "jump"
        body.proxy_host = "10.0.0.1"
        body.proxy_port = 22
        body.proxy_username = "u"
        body.proxy_password = ""
        body.proxy_private_key = ""
        with pytest.raises(HTTPException):
            _validate_main_proxy(body)

    def test_socks5_with_pass_no_user(self):
        body = MagicMock()
        body.proxy_type = "socks5"
        body.proxy_host = "10.0.0.1"
        body.proxy_port = 1080
        body.proxy_password = "pass"
        body.proxy_username = ""
        with pytest.raises(HTTPException):
            _validate_main_proxy(body)


class TestValidateExecProxy_v3:
    def test_none(self):
        body = MagicMock()
        body.exec_proxy_type = "none"
        _validate_exec_proxy(body)

    def test_invalid_type(self):
        body = MagicMock()
        body.exec_proxy_type = "jump"
        with pytest.raises(HTTPException):
            _validate_exec_proxy(body)

    def test_socks5_no_host(self):
        body = MagicMock()
        body.exec_proxy_type = "socks5"
        body.exec_proxy_host = ""
        body.exec_proxy_port = 1080
        body.exec_proxy_password = ""
        body.exec_proxy_username = ""
        body.exec_jump_host = ""
        body.exec_jump_port = 22
        with pytest.raises(HTTPException):
            _validate_exec_proxy(body)

    def test_socks5_with_pass_no_user(self):
        body = MagicMock()
        body.exec_proxy_type = "socks5"
        body.exec_proxy_host = "10.0.0.1"
        body.exec_proxy_port = 1080
        body.exec_proxy_password = "pass"
        body.exec_proxy_username = ""
        body.exec_jump_host = ""
        body.exec_jump_port = 22
        with pytest.raises(HTTPException):
            _validate_exec_proxy(body)

    def test_jump_bad_port(self):
        body = MagicMock()
        body.exec_proxy_type = "socks5"
        body.exec_proxy_host = "10.0.0.1"
        body.exec_proxy_port = 1080
        body.exec_proxy_password = ""
        body.exec_proxy_username = ""
        body.exec_jump_host = "10.0.0.2"
        body.exec_jump_port = 0
        with pytest.raises(HTTPException):
            _validate_exec_proxy(body)


class TestValidateAttackerTarget_v3:
    def test_valid(self):
        with patch("app.routers.system_modules._require_attacker_module_enabled"):
            body = MagicMock()
            body.name = "test"
            body.host = "10.0.0.1"
            body.username = "root"
            body.port = 22
            body.proxy_type = "none"
            body.exec_proxy_type = "none"
            body.is_operator = True
            body.runs_pivot = False
            _validate_attacker_target(body)

    def test_missing_name(self):
        with patch("app.routers.system_modules._require_attacker_module_enabled"):
            body = MagicMock()
            body.name = ""
            body.host = "10.0.0.1"
            body.username = "root"
            with pytest.raises(HTTPException):
                _validate_attacker_target(body)

    def test_neither_operator_nor_pivot(self):
        with patch("app.routers.system_modules._require_attacker_module_enabled"):
            body = MagicMock()
            body.name = "t"
            body.host = "10.0.0.1"
            body.username = "root"
            body.port = 22
            body.proxy_type = "none"
            body.exec_proxy_type = "none"
            body.is_operator = False
            body.runs_pivot = False
            with pytest.raises(HTTPException):
                _validate_attacker_target(body)


class TestResolveNextCredentials_v3:
    def test_body_takes_priority(self):
        body = MagicMock()
        body.password = "newpass"
        body.private_key = "newkey"
        body.proxy_password = "proxypass"
        body.proxy_private_key = "proxykey"
        body.exec_proxy_password = "execpass"
        target = {"password": "old", "private_key": "oldkey", "proxy_password": "old",
                  "proxy_private_key": "old", "exec_proxy_password": "old"}
        r = _resolve_next_credentials(body, target)
        assert r["password"] == "newpass"
        assert r["private_key"] == "newkey"

    def test_fallback_to_target(self):
        body = MagicMock()
        body.password = ""
        body.private_key = ""
        body.proxy_password = ""
        body.proxy_private_key = ""
        body.exec_proxy_password = ""
        target = {"password": "old", "private_key": "oldkey", "proxy_password": "old",
                  "proxy_private_key": "old", "exec_proxy_password": "old"}
        r = _resolve_next_credentials(body, target)
        assert r["password"] == "old"
        assert r["private_key"] == "oldkey"


class TestTemplates_v3:
    def test_backend_template(self):
        assert "BackendModule" in MODULE_TEMPLATE

    def test_frontend_template(self):
        assert "moduleRegistry" in FRONTEND_MODULE_TEMPLATE

    def test_module_name_re(self):
        assert MODULE_NAME_RE.match("my_module")
        assert MODULE_NAME_RE.match("test-module")
        assert not MODULE_NAME_RE.match("bad module!")
