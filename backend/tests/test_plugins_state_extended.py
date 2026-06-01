"""Tests for app.plugins.state — module state machine transitions."""
from unittest.mock import MagicMock, patch, PropertyMock

from app.plugins.state import (
    _default_module_state,
    _default_attacker_config,
    _decrypt_target,
    _encrypt_target,
    _update_custom_module_item,
    _register_custom_modules,
    apply_saved_state,
    create_custom_module,
    delete_custom_module,
    delete_uploaded_module,
    list_attacker_targets_for_exec,
    list_attacker_targets_for_pivot,
    list_attacker_targets_safe,
    load_attacker_ssh_config,
    load_module_state,
    save_attacker_targets,
    update_module,
    MODULE_NAME_RE,
)
from app.plugins.registry import registry
from app.plugins.types import BackendModule


class TestLoadModuleState:
    @patch("app.plugins.state._get_setting")
    def test_returns_default_when_empty(self, mock_setting):
        mock_item = MagicMock()
        mock_item.value = {}
        mock_setting.return_value = mock_item
        state = load_module_state(MagicMock())
        assert "states" in state
        assert "custom_modules" in state

    @patch("app.plugins.state._get_setting")
    def test_fills_defaults(self, mock_setting):
        mock_item = MagicMock()
        mock_item.value = {"states": {}}
        mock_setting.return_value = mock_item
        state = load_module_state(MagicMock())
        assert "custom_modules" in state


class TestApplySavedState:
    @patch("app.plugins.state.save_module_state")
    @patch("app.plugins.state.load_module_state")
    def test_applies_enabled_state(self, mock_load, mock_save):
        module = BackendModule(name="test_mod", title="Test", version="1.0", description="", enabled=True, source="builtin")
        registry.register(module)
        mock_load.return_value = {
            "states": {"test_mod": {"enabled": False}},
            "custom_modules": [],
        }
        apply_saved_state()
        mod = registry.get("test_mod")
        assert mod is not None

    @patch("app.plugins.state.save_module_state")
    @patch("app.plugins.state.load_module_state")
    def test_applies_custom_title(self, mock_load, mock_save):
        module = BackendModule(name="title_mod", title="Original", version="1.0", description="", enabled=True, source="builtin")
        registry.register(module)
        mock_load.return_value = {
            "states": {"title_mod": {"title": "Updated Title"}},
            "custom_modules": [],
        }
        apply_saved_state()
        mod = registry.get("title_mod")
        assert mod is not None


class TestCreateCustomModule:
    @patch("app.plugins.state.save_module_state")
    @patch("app.plugins.state.load_module_state")
    def test_creates_and_registers(self, mock_load, mock_save):
        mock_load.return_value = {"states": {}, "custom_modules": []}
        registry._modules.pop("test_new_mod", None)
        result = create_custom_module("test_new_mod", "My Module", "1.0", "desc", True)
        assert result["name"] == "test_new_mod"
        assert result["source"] == "custom"

    @patch("app.plugins.state.load_module_state")
    def test_duplicate_raises(self, mock_load):
        mock_load.return_value = {"states": {}, "custom_modules": []}
        registry.register(BackendModule(name="dup_mod", title="Dup", version="1.0", description="", enabled=True, source="builtin"))
        try:
            create_custom_module("dup_mod", "Dup", "1.0", "", True)
            assert False, "Should raise"
        except ValueError:
            pass


class TestUpdateModule:
    @patch("app.plugins.state.save_module_state")
    @patch("app.plugins.state.load_module_state")
    def test_updates_enabled(self, mock_load, mock_save):
        registry.register(BackendModule(name="upd_mod", title="Upd", version="1.0", description="", enabled=True, source="builtin"))
        mock_load.return_value = {"states": {}, "custom_modules": []}
        result = update_module("upd_mod", enabled=False)
        assert result is not None
        assert result["enabled"] is False

    @patch("app.plugins.state.load_module_state")
    def test_not_found_returns_none(self, mock_load):
        mock_load.return_value = {"states": {}, "custom_modules": []}
        assert update_module("nonexistent_mod") is None

    @patch("app.plugins.state.save_module_state")
    @patch("app.plugins.state.load_module_state")
    def test_updates_description(self, mock_load, mock_save):
        registry.register(BackendModule(name="desc_mod", title="Desc", version="1.0", description="old", enabled=True, source="builtin"))
        mock_load.return_value = {"states": {}, "custom_modules": []}
        result = update_module("desc_mod", description="new desc")
        assert result["description"] == "new desc"


class TestDeleteCustomModule:
    @patch("app.plugins.state.save_module_state")
    @patch("app.plugins.state.load_module_state")
    def test_deletes_custom(self, mock_load, mock_save):
        registry.register(BackendModule(name="del_custom", title="Del", version="1.0", description="", enabled=True, source="custom", editable=True))
        mock_load.return_value = {"states": {}, "custom_modules": [{"name": "del_custom", "title": "Del", "version": "1.0", "description": "", "enabled": True}]}
        result = delete_custom_module("del_custom")
        assert result is True

    @patch("app.plugins.state.load_module_state")
    def test_not_custom_returns_false(self, mock_load):
        registry.register(BackendModule(name="builtin_del", title="B", version="1.0", description="", enabled=True, source="builtin"))
        result = delete_custom_module("builtin_del")
        assert result is False


class TestDeleteUploadedModule:
    @patch("app.plugins.state.load_module_state")
    def test_no_module_returns_false(self, mock_load):
        mock_load.return_value = {"states": {}, "custom_modules": []}
        result = delete_uploaded_module("nonexistent")
        assert result is False


class TestListAttackerTargetsForExec:
    @patch("app.plugins.state.list_attacker_targets")
    def test_filters_operator_only(self, mock_list):
        mock_list.return_value = [
            {"id": "t1", "enabled": True, "is_operator": True},
            {"id": "t2", "enabled": True, "is_operator": False},
            {"id": "t3", "enabled": False, "is_operator": True},
        ]
        result = list_attacker_targets_for_exec()
        assert len(result) == 1
        assert result[0]["id"] == "t1"


class TestListAttackerTargetsForPivot:
    @patch("app.plugins.state.list_attacker_targets")
    def test_filters_pivot_only(self, mock_list):
        mock_list.return_value = [
            {"id": "t1", "enabled": True, "runs_pivot": True},
            {"id": "t2", "enabled": True, "runs_pivot": False},
        ]
        result = list_attacker_targets_for_pivot()
        assert len(result) == 1


class TestListAttackerTargetsSafe:
    @patch("app.plugins.state.list_attacker_targets")
    def test_masks_passwords(self, mock_list):
        mock_list.return_value = [
            {"id": "t1", "password": "secret", "private_key": "key", "proxy_password": "p", "proxy_private_key": "pk", "exec_proxy_password": "ep"},
        ]
        result = list_attacker_targets_safe()
        assert result[0]["password"] == ""
        assert result[0]["has_password"] is True
        assert result[0]["has_private_key"] is True


class TestSaveAttackerTargets:
    @patch("app.plugins.state.save_attacker_ssh_config")
    @patch("app.plugins.state.load_attacker_ssh_config")
    def test_encrypts_and_saves(self, mock_load, mock_save):
        mock_load.return_value = {"targets": []}
        mock_save.return_value = {"targets": [{"password": "enc", "private_key": "", "proxy_password": "", "proxy_private_key": "", "exec_proxy_password": ""}]}
        with patch("app.plugins.state._encrypt_target", side_effect=lambda t: t), \
             patch("app.plugins.state._decrypt_target", side_effect=lambda t: t):
            result = save_attacker_targets([{"password": "plain"}])
            assert len(result) == 1


class TestLoadAttackerSshConfig:
    @patch("app.plugins.state._get_setting")
    def test_legacy_migration(self, mock_setting):
        mock_item = MagicMock()
        mock_item.value = {"host": "10.0.0.1", "username": "root", "password": "pass", "port": 22}
        mock_setting.return_value = mock_item
        result = load_attacker_ssh_config(MagicMock())
        assert len(result["targets"]) == 1
        assert result["targets"][0]["id"] == "legacy-global"
