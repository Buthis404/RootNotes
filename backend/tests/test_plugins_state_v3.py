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


class TestDecryptTarget:
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


class TestEncryptTarget:
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


class TestListAttackerTargetsSafe:
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


class TestSaveAttackerTargets:
    def test_round_trip(self):
        with patch("app.plugins.state.load_attacker_ssh_config", return_value={"targets": []}):
            with patch("app.plugins.state.save_attacker_ssh_config", return_value={
                "targets": [{"password": "enc", "private_key": "enc", "proxy_password": "",
                             "proxy_private_key": "", "exec_proxy_password": ""}]
            }):
                with patch("app.plugins.state._decrypt_target", return_value={"password": "dec"}):
                    r = save_attacker_targets([{"password": "pass"}])
                    assert len(r) == 1


class TestRegisterCustomModules:
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


class TestDefaultModuleState:
    def test_structure(self):
        s = _default_module_state()
        assert "states" in s
        assert "custom_modules" in s


class TestDefaultAttackerConfig:
    def test_structure(self):
        c = _default_attacker_config()
        assert "targets" in c
        assert isinstance(c["targets"], list)


class TestModuleNameRe:
    def test_valid(self):
        assert MODULE_NAME_RE.match("my_module")
        assert MODULE_NAME_RE.match("test-module")
        assert MODULE_NAME_RE.match("abc123")

    def test_invalid(self):
        assert not MODULE_NAME_RE.match("")
        assert not MODULE_NAME_RE.match("a")
        assert not MODULE_NAME_RE.match("bad module!")
