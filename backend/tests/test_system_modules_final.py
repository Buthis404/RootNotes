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


class TestCheckAstImportNode:
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


class TestCheckAstCallNode:
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


class TestScanAstTree:
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


class TestValidateModuleSource:
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


class TestValidateMainProxy:
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


class TestValidateExecProxy:
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


class TestValidateAttackerTarget:
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


class TestResolveNextCredentials:
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


class TestTemplates:
    def test_module_template(self):
        assert "BackendModule" in MODULE_TEMPLATE

    def test_frontend_template(self):
        assert "moduleRegistry" in FRONTEND_MODULE_TEMPLATE
