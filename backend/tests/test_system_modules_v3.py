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


class TestCheckAstImportNode:
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


class TestCheckAstCallNode:
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


class TestScanAstTree:
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


class TestValidateModuleSource:
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


class TestValidateMainProxy:
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


class TestValidateExecProxy:
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


class TestValidateAttackerTarget:
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


class TestResolveNextCredentials:
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


class TestTemplates:
    def test_backend_template(self):
        assert "BackendModule" in MODULE_TEMPLATE

    def test_frontend_template(self):
        assert "moduleRegistry" in FRONTEND_MODULE_TEMPLATE

    def test_module_name_re(self):
        assert MODULE_NAME_RE.match("my_module")
        assert MODULE_NAME_RE.match("test-module")
        assert not MODULE_NAME_RE.match("bad module!")
