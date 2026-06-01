"""Consolidated tests for test_plugins_state (merged variant files)."""

# ════════ from test_plugins_state.py ════════
import pytest
from unittest.mock import MagicMock, patch

from app.plugins.state import (
    _default_module_state,
    _default_attacker_config,
    _decrypt_target,
    _encrypt_target,
    _update_custom_module_item,
    _register_custom_modules,
    MODULE_NAME_RE,
)
from app.plugins.registry import registry
from app.plugins.types import BackendModule


class TestDefaultModuleState_base:
    def test_returns_dict(self):
        state = _default_module_state()
        assert "states" in state
        assert "custom_modules" in state
        assert state["states"] == {}
        assert state["custom_modules"] == []


class TestDefaultAttackerConfig_base:
    def test_returns_dict(self):
        config = _default_attacker_config()
        assert "targets" in config
        assert config["targets"] == []


class TestModuleNameRe_base:
    def test_valid_names(self):
        assert MODULE_NAME_RE.match("my-module") is not None
        assert MODULE_NAME_RE.match("nmap_parser") is not None
        assert MODULE_NAME_RE.match("ab") is not None
        assert MODULE_NAME_RE.match("Module123") is not None

    def test_invalid_names(self):
        assert MODULE_NAME_RE.match("a") is None
        assert MODULE_NAME_RE.match("") is None
        assert MODULE_NAME_RE.match("a" * 65) is None
        assert MODULE_NAME_RE.match("has space") is None
        assert MODULE_NAME_RE.match("has.dot") is None


class TestDecryptTarget_base:
    @patch("app.plugins.state.decrypt_str", side_effect=lambda x: f"dec_{x}")
    def test_decrypts_fields(self, mock_decrypt):
        target = {"password": "enc_pass", "private_key": "enc_key", "proxy_password": "", "proxy_private_key": "", "exec_proxy_password": ""}
        result = _decrypt_target(target)
        assert result["password"] == "dec_enc_pass"
        assert result["private_key"] == "dec_enc_key"

    @patch("app.plugins.state.decrypt_str", side_effect=lambda x: f"dec_{x}")
    def test_sets_defaults(self, mock_decrypt):
        target = {"password": "", "private_key": "", "proxy_password": "", "proxy_private_key": "", "exec_proxy_password": ""}
        result = _decrypt_target(target)
        assert result["is_operator"] is True
        assert result["runs_pivot"] is True

    @patch("app.plugins.state.decrypt_str", side_effect=lambda x: f"dec_{x}")
    def test_preserves_existing_flags(self, mock_decrypt):
        target = {"password": "", "private_key": "", "proxy_password": "", "proxy_private_key": "", "exec_proxy_password": "", "is_operator": False, "runs_pivot": False}
        result = _decrypt_target(target)
        assert result["is_operator"] is False
        assert result["runs_pivot"] is False

    @patch("app.plugins.state.decrypt_str", side_effect=lambda x: f"dec_{x}")
    def test_does_not_mutate_input(self, mock_decrypt):
        target = {"password": "secret", "private_key": "", "proxy_password": "", "proxy_private_key": "", "exec_proxy_password": ""}
        _decrypt_target(target)
        assert target["password"] == "secret"


class TestEncryptTarget_base:
    @patch("app.plugins.state.encrypt_str", side_effect=lambda x: f"enc_{x}")
    def test_encrypts_fields(self, mock_encrypt):
        target = {"password": "plain", "private_key": "key", "proxy_password": "", "proxy_private_key": "", "exec_proxy_password": ""}
        result = _encrypt_target(target)
        assert result["password"] == "enc_plain"
        assert result["private_key"] == "enc_key"

    @patch("app.plugins.state.encrypt_str", side_effect=lambda x: f"enc_{x}")
    def test_does_not_mutate_input(self, mock_encrypt):
        target = {"password": "secret", "private_key": "", "proxy_password": "", "proxy_private_key": "", "exec_proxy_password": ""}
        _encrypt_target(target)
        assert target["password"] == "secret"


class TestUpdateCustomModuleItem_base:
    def test_updates_fields(self):
        module = MagicMock()
        module.title = "New Title"
        module.version = "2.0.0"
        module.description = "Updated"
        item = {"title": "Old", "version": "1.0.0", "description": "Old", "enabled": True}
        _update_custom_module_item(item, module, None)
        assert item["title"] == "New Title"
        assert item["version"] == "2.0.0"
        assert item["description"] == "Updated"
        assert item["enabled"] is True

    def test_sets_enabled(self):
        module = MagicMock()
        module.title = "T"
        module.version = "1.0"
        module.description = ""
        item = {"title": "", "version": "", "description": "", "enabled": True}
        _update_custom_module_item(item, module, False)
        assert item["enabled"] is False


class TestRegisterCustomModules_base:
    def test_registers_modules(self):
        reg = MagicMock()
        custom_modules = [
            {"name": "custom1", "title": "Custom 1", "version": "1.0", "description": "test", "enabled": True},
            {"name": "custom2", "title": "Custom 2"},
        ]
        with patch("app.plugins.state.registry", reg):
            _register_custom_modules(custom_modules)
            assert reg.register.call_count == 2

    def test_skips_no_name(self):
        reg = MagicMock()
        custom_modules = [
            {"name": "", "title": "Empty name"},
            {"name": "valid", "title": "Valid"},
        ]
        with patch("app.plugins.state.registry", reg):
            _register_custom_modules(custom_modules)
            assert reg.register.call_count == 1

    def test_empty_list(self):
        reg = MagicMock()
        with patch("app.plugins.state.registry", reg):
            _register_custom_modules([])
            reg.register.assert_not_called()


# ════════ from test_plugins_state_extended.py ════════
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


class TestApplySavedState_extended:
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


class TestDeleteUploadedModule_extended:
    @patch("app.plugins.state.load_module_state")
    def test_no_module_returns_false(self, mock_load):
        mock_load.return_value = {"states": {}, "custom_modules": []}
        result = delete_uploaded_module("nonexistent")
        assert result is False


class TestListAttackerTargetsForExec_extended:
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


class TestListAttackerTargetsForPivot_extended:
    @patch("app.plugins.state.list_attacker_targets")
    def test_filters_pivot_only(self, mock_list):
        mock_list.return_value = [
            {"id": "t1", "enabled": True, "runs_pivot": True},
            {"id": "t2", "enabled": True, "runs_pivot": False},
        ]
        result = list_attacker_targets_for_pivot()
        assert len(result) == 1


class TestListAttackerTargetsSafe_extended:
    @patch("app.plugins.state.list_attacker_targets")
    def test_masks_passwords(self, mock_list):
        mock_list.return_value = [
            {"id": "t1", "password": "secret", "private_key": "key", "proxy_password": "p", "proxy_private_key": "pk", "exec_proxy_password": "ep"},
        ]
        result = list_attacker_targets_safe()
        assert result[0]["password"] == ""
        assert result[0]["has_password"] is True
        assert result[0]["has_private_key"] is True


class TestSaveAttackerTargets_extended:
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


# ════════ from test_plugins_state_final.py ════════
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


class TestDefaultModuleState_final:
    def test_structure(self):
        state = _default_module_state()
        assert "states" in state
        assert "custom_modules" in state
        assert state["states"] == {}
        assert state["custom_modules"] == []


class TestDefaultAttackerConfig_final:
    def test_structure(self):
        cfg = _default_attacker_config()
        assert "targets" in cfg
        assert cfg["targets"] == []


class TestDecryptTarget_final:
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


class TestEncryptTarget_final:
    def test_encrypts(self):
        from app.core.crypto import decrypt_str
        target = {"password": "pass", "private_key": "key", "proxy_password": "pp", "proxy_private_key": "pk", "exec_proxy_password": "ep"}
        result = _encrypt_target(target)
        assert result["password"] != "pass"
        assert decrypt_str(result["password"]) == "pass"


class TestListAttackerTargetsForExec_final:
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


class TestListAttackerTargetsForPivot_final:
    def test_filters_non_pivot(self):
        with patch("app.plugins.state.list_attacker_targets", return_value=[
            {"id": "t1", "enabled": True, "runs_pivot": True},
            {"id": "t2", "enabled": True, "runs_pivot": False},
        ]):
            result = list_attacker_targets_for_pivot()
            ids = [t["id"] for t in result]
            assert "t1" in ids
            assert "t2" not in ids


class TestListAttackerTargetsSafe_final:
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


class TestRegisterCustomModules_final:
    def test_registers(self):
        with patch("app.plugins.state.registry") as mock_reg:
            _register_custom_modules([{"name": "test_mod", "title": "Test", "version": "1.0", "description": "desc", "enabled": True}])
            mock_reg.register.assert_called_once()

    def test_skips_empty_name(self):
        with patch("app.plugins.state.registry") as mock_reg:
            _register_custom_modules([{"name": ""}])
            mock_reg.register.assert_not_called()


class TestUpdateCustomModuleItem_final:
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


class TestApplySavedState_final:
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


class TestDeleteUploadedModule_final:
    def test_not_uploaded(self):
        with patch("app.plugins.state.registry") as mock_reg:
            m = MagicMock()
            m.source = "custom"
            mock_reg.get.return_value = m
            assert delete_uploaded_module("mod1") is False


class TestModuleNameRe_final:
    def test_valid(self):
        assert MODULE_NAME_RE.match("my-module_1")

    def test_too_short(self):
        assert not MODULE_NAME_RE.match("a")

    def test_special_chars(self):
        assert not MODULE_NAME_RE.match("my module!")


# ════════ from test_plugins_state_v3.py ════════
import pytest
from unittest.mock import MagicMock, patch

from app.plugins.state import (
    _decrypt_target,
    _encrypt_target,
    list_attacker_targets_safe,
    save_attacker_targets,
    _register_custom_modules,
    _default_module_state,
    _default_attacker_config,
    MODULE_NAME_RE,
)


class TestDecryptTarget_v3:
    def test_basic(self):
        with patch("app.plugins.state.decrypt_str", return_value="decrypted"):
            t = _decrypt_target({"password": "enc1", "private_key": "enc2"})
            assert t["password"] == "decrypted"
            assert t["private_key"] == "decrypted"

    def test_defaults_operator(self):
        with patch("app.plugins.state.decrypt_str", return_value=""):
            t = _decrypt_target({})
            assert t["is_operator"] is True
            assert t["runs_pivot"] is True

    def test_preserves_other_fields(self):
        with patch("app.plugins.state.decrypt_str", return_value=""):
            t = _decrypt_target({"host": "10.0.0.1", "port": 22})
            assert t["host"] == "10.0.0.1"
            assert t["port"] == 22


class TestEncryptTarget_v3:
    def test_basic(self):
        with patch("app.plugins.state.encrypt_str", return_value="encrypted"):
            t = _encrypt_target({"password": "pass", "private_key": "key"})
            assert t["password"] == "encrypted"
            assert t["private_key"] == "encrypted"

    def test_proxy_fields(self):
        with patch("app.plugins.state.encrypt_str", return_value="enc"):
            t = _encrypt_target({"proxy_password": "p", "proxy_private_key": "k", "exec_proxy_password": "e"})
            assert t["proxy_password"] == "enc"
            assert t["proxy_private_key"] == "enc"
            assert t["exec_proxy_password"] == "enc"


class TestListAttackerTargetsSafe_v3:
    def test_masks_secrets(self):
        with patch("app.plugins.state.list_attacker_targets", return_value=[
            {"id": "t1", "password": "pass", "private_key": "key",
             "proxy_password": "p", "proxy_private_key": "k", "exec_proxy_password": "e"},
        ]):
            safe = list_attacker_targets_safe()
            assert safe[0]["password"] == ""
            assert safe[0]["has_password"] is True
            assert safe[0]["has_private_key"] is True
            assert safe[0]["has_proxy_password"] is True
            assert safe[0]["has_proxy_private_key"] is True
            assert safe[0]["has_exec_proxy_password"] is True

    def test_no_secrets(self):
        with patch("app.plugins.state.list_attacker_targets", return_value=[
            {"id": "t1"},
        ]):
            safe = list_attacker_targets_safe()
            assert safe[0]["has_password"] is False


class TestSaveAttackerTargets_v3:
    def test_round_trip(self):
        with patch("app.plugins.state.load_attacker_ssh_config", return_value={"targets": []}):
            with patch("app.plugins.state.save_attacker_ssh_config", return_value={
                "targets": [{"password": "enc", "private_key": "enc", "proxy_password": "",
                             "proxy_private_key": "", "exec_proxy_password": ""}]
            }):
                with patch("app.plugins.state._decrypt_target", return_value={"password": "dec"}):
                    r = save_attacker_targets([{"password": "pass"}])
                    assert len(r) == 1


class TestRegisterCustomModules_v3:
    def test_basic(self):
        with patch("app.plugins.state.registry") as mock_reg:
            _register_custom_modules([
                {"name": "test_mod", "title": "Test", "version": "1.0", "enabled": True}
            ])
            mock_reg.register.assert_called_once()

    def test_skip_empty_name(self):
        with patch("app.plugins.state.registry") as mock_reg:
            _register_custom_modules([{"name": ""}])
            mock_reg.register.assert_not_called()

    def test_defaults(self):
        with patch("app.plugins.state.registry") as mock_reg:
            _register_custom_modules([{"name": "m1"}])
            call_args = mock_reg.register.call_args[0][0]
            assert call_args.name == "m1"
            assert call_args.version == "1.0.0"
            assert call_args.enabled is True


class TestDefaultModuleState_v3:
    def test_structure(self):
        s = _default_module_state()
        assert "states" in s
        assert "custom_modules" in s


class TestDefaultAttackerConfig_v3:
    def test_structure(self):
        c = _default_attacker_config()
        assert "targets" in c
        assert isinstance(c["targets"], list)


class TestModuleNameRe_v3:
    def test_valid(self):
        assert MODULE_NAME_RE.match("my_module")
        assert MODULE_NAME_RE.match("test-module")
        assert MODULE_NAME_RE.match("abc123")

    def test_invalid(self):
        assert not MODULE_NAME_RE.match("")
        assert not MODULE_NAME_RE.match("a")
        assert not MODULE_NAME_RE.match("bad module!")
