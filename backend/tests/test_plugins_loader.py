"""Tests for app.plugins.loader — module registration and discovery."""

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from app.plugins.loader import (
    _nmap_parser_placeholder,
    _register_builtin_modules,
    load_plugin_module,
    initialize,
)
from app.plugins.registry import ModuleRegistry
from app.plugins.types import BackendModule


class TestNmapParserPlaceholder:
    def test_returns_empty_list(self):
        assert _nmap_parser_placeholder("any xml") == []


class TestRegisterBuiltinModules:
    def test_registers_topology(self):
        reg = ModuleRegistry()
        with patch("app.plugins.loader.registry", reg):
            _register_builtin_modules()
            assert reg.get("topology") is not None
            assert reg.get("topology").enabled is True

    def test_registers_nmap_parser(self):
        reg = ModuleRegistry()
        with patch("app.plugins.loader.registry", reg):
            _register_builtin_modules()
            assert reg.get("nmap_parser") is not None
            nmap_connectors = [c.key for c in reg.get("nmap_parser").connectors]
            assert "nmap" in nmap_connectors
            assert "netexec" in nmap_connectors

    def test_registers_attacker_ssh(self):
        reg = ModuleRegistry()
        with patch("app.plugins.loader.registry", reg):
            _register_builtin_modules()
            assert reg.get("attacker_ssh") is not None

    def test_registers_c2_integration(self):
        reg = ModuleRegistry()
        with patch("app.plugins.loader.registry", reg):
            _register_builtin_modules()
            assert reg.get("c2_integration") is not None

    def test_total_builtin_count(self):
        reg = ModuleRegistry()
        with patch("app.plugins.loader.registry", reg):
            _register_builtin_modules()
            assert len(reg.get_all()) >= 4


class TestLoadPluginModule:
    def test_loads_valid_module(self):
        reg = ModuleRegistry()
        mock_mod = MagicMock()
        mock_mod.MODULE = BackendModule(name="test_plugin", version="1.0.0", title="Test Plugin")
        with patch("app.plugins.loader.registry", reg), \
             patch("importlib.import_module", return_value=mock_mod):
            result = load_plugin_module("test_plugin")
            assert result.name == "test_plugin"
            assert reg.get("test_plugin") is not None

    def test_rejects_module_without_module_attr(self):
        mock_mod = MagicMock(spec=[])
        with patch("importlib.import_module", return_value=mock_mod):
            with pytest.raises(ValueError, match="must define MODULE"):
                load_plugin_module("bad_plugin")

    def test_builtin_source_becomes_uploaded(self):
        reg = ModuleRegistry()
        mock_mod = MagicMock()
        mock_mod.MODULE = BackendModule(name="p1", version="1.0", source="builtin")
        with patch("app.plugins.loader.registry", reg), \
             patch("importlib.import_module", return_value=mock_mod):
            result = load_plugin_module("p1")
            assert result.source == "uploaded"
            assert result.editable is True

    def test_empty_title_gets_name(self):
        reg = ModuleRegistry()
        mock_mod = MagicMock()
        mock_mod.MODULE = BackendModule(name="myplugin", version="1.0", title="")
        with patch("app.plugins.loader.registry", reg), \
             patch("importlib.import_module", return_value=mock_mod):
            result = load_plugin_module("myplugin")
            assert result.title == "myplugin"


class TestInitialize:
    def test_calls_all_steps(self):
        reg = ModuleRegistry()
        with patch("app.plugins.loader.registry", reg), \
             patch("app.plugins.loader._register_builtin_modules") as mock_builtin, \
             patch("app.plugins.loader.load_plugin_modules", return_value=[]), \
             patch("app.plugins.loader.apply_saved_state"):
            initialize()
            mock_builtin.assert_called_once()

    def test_with_app_includes_routers(self):
        reg = ModuleRegistry()
        mod_with_router = BackendModule(name="routed", version="1.0", enabled=True)
        mock_router = MagicMock()
        mod_with_router.router = mock_router
        reg.register(mod_with_router)

        mock_app = MagicMock()
        with patch("app.plugins.loader.registry", reg), \
             patch("app.plugins.loader._register_builtin_modules"), \
             patch("app.plugins.loader.load_plugin_modules", return_value=[]), \
             patch("app.plugins.loader.apply_saved_state"):
            initialize(mock_app)
            mock_app.include_router.assert_called_with(mock_router)
