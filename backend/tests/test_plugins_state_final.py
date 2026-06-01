import pytest
from unittest.mock import MagicMock, patch

from app.plugins.state import (
    _default_module_state,
    _default_attacker_config,
    _decrypt_target,
    _encrypt_target,
    list_attacker_targets_for_exec,
    list_attacker_targets_for_pivot,
    list_attacker_targets_safe,
    _register_custom_modules,
    _update_custom_module_item,
    apply_saved_state,
    list_modules,
    delete_uploaded_module,
    MODULE_NAME_RE,
)


class TestDefaultModuleState:
    def test_structure(self):
        state = _default_module_state()
        assert "states" in state
        assert "custom_modules" in state
        assert state["states"] == {}
        assert state["custom_modules"] == []


class TestDefaultAttackerConfig:
    def test_structure(self):
        cfg = _default_attacker_config()
        assert "targets" in cfg
        assert cfg["targets"] == []


class TestDecryptTarget:
    def test_decrypts_passwords(self):
        from app.core.crypto import encrypt_str
        target = {
            "password": encrypt_str("secret"),
            "private_key": encrypt_str("key"),
            "proxy_password": "",
            "proxy_private_key": "",
            "exec_proxy_password": "",
        }
        result = _decrypt_target(target)
        assert result["password"] == "secret"
        assert result["private_key"] == "key"

    def test_sets_defaults(self):
        result = _decrypt_target({})
        assert result["is_operator"] is True
        assert result["runs_pivot"] is True


class TestEncryptTarget:
    def test_encrypts(self):
        from app.core.crypto import decrypt_str
        target = {"password": "pass", "private_key": "key", "proxy_password": "pp", "proxy_private_key": "pk", "exec_proxy_password": "ep"}
        result = _encrypt_target(target)
        assert result["password"] != "pass"
        assert decrypt_str(result["password"]) == "pass"


class TestListAttackerTargetsForExec:
    def test_filters_non_operator(self):
        with patch("app.plugins.state.list_attacker_targets", return_value=[
            {"id": "t1", "enabled": True, "is_operator": True},
            {"id": "t2", "enabled": True, "is_operator": False},
            {"id": "t3", "enabled": False, "is_operator": True},
        ]):
            result = list_attacker_targets_for_exec()
            ids = [t["id"] for t in result]
            assert "t1" in ids
            assert "t2" not in ids
            assert "t3" not in ids


class TestListAttackerTargetsForPivot:
    def test_filters_non_pivot(self):
        with patch("app.plugins.state.list_attacker_targets", return_value=[
            {"id": "t1", "enabled": True, "runs_pivot": True},
            {"id": "t2", "enabled": True, "runs_pivot": False},
        ]):
            result = list_attacker_targets_for_pivot()
            ids = [t["id"] for t in result]
            assert "t1" in ids
            assert "t2" not in ids


class TestListAttackerTargetsSafe:
    def test_masks_secrets(self):
        with patch("app.plugins.state.list_attacker_targets", return_value=[
            {"id": "t1", "password": "secret", "private_key": "key", "proxy_password": "pp", "proxy_private_key": "pk", "exec_proxy_password": "ep"},
        ]):
            result = list_attacker_targets_safe()
            assert result[0]["password"] == ""
            assert result[0]["private_key"] == ""
            assert result[0]["proxy_password"] == ""
            assert result[0]["proxy_private_key"] == ""
            assert result[0]["exec_proxy_password"] == ""
            assert result[0]["has_password"] is True
            assert result[0]["has_private_key"] is True


class TestRegisterCustomModules:
    def test_registers(self):
        with patch("app.plugins.state.registry") as mock_reg:
            _register_custom_modules([{"name": "test_mod", "title": "Test", "version": "1.0", "description": "desc", "enabled": True}])
            mock_reg.register.assert_called_once()

    def test_skips_empty_name(self):
        with patch("app.plugins.state.registry") as mock_reg:
            _register_custom_modules([{"name": ""}])
            mock_reg.register.assert_not_called()


class TestUpdateCustomModuleItem:
    def test_updates(self):
        module = MagicMock()
        module.title = "New Title"
        module.version = "2.0"
        module.description = "New desc"
        item = {"title": "Old", "version": "1.0", "description": "Old", "enabled": True}
        _update_custom_module_item(item, module, False)
        assert item["title"] == "New Title"

    def test_enabled_none(self):
        module = MagicMock()
        module.title = "T"
        module.version = "V"
        module.description = "D"
        item = {"title": "", "version": "", "description": "", "enabled": True}
        _update_custom_module_item(item, module, None)
        assert item["enabled"] is True

    def test_enabled_false(self):
        module = MagicMock()
        module.title = "T"
        module.version = "V"
        module.description = "D"
        item = {"title": "", "version": "", "description": "", "enabled": True}
        _update_custom_module_item(item, module, False)
        assert item["enabled"] is False


class TestApplySavedState:
    def test_applies(self):
        with patch("app.plugins.state.load_module_state", return_value={
            "states": {"mod1": {"enabled": False, "title": "T", "version": "V", "description": "D"}},
            "custom_modules": [],
        }), patch("app.plugins.state._register_custom_modules"), \
             patch("app.plugins.state.registry") as mock_reg:
            mock_mod = MagicMock()
            mock_reg.get.return_value = mock_mod
            apply_saved_state()
            assert mock_mod.enabled is False
            assert mock_mod.title == "T"


class TestListModules:
    def test_returns_list(self):
        with patch("app.plugins.state.registry") as mock_reg:
            m = MagicMock()
            m.to_dict.return_value = {"name": "mod1"}
            m.source = "builtin"
            m.title = "M"
            m.name = "mod1"
            mock_reg.get_all.return_value = [m]
            result = list_modules()
            assert len(result) == 1


class TestDeleteUploadedModule:
    def test_not_uploaded(self):
        with patch("app.plugins.state.registry") as mock_reg:
            m = MagicMock()
            m.source = "custom"
            mock_reg.get.return_value = m
            assert delete_uploaded_module("mod1") is False


class TestModuleNameRe:
    def test_valid(self):
        assert MODULE_NAME_RE.match("my-module_1")

    def test_too_short(self):
        assert not MODULE_NAME_RE.match("a")

    def test_special_chars(self):
        assert not MODULE_NAME_RE.match("my module!")
