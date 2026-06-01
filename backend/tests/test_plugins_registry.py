"""Tests for app.plugins.registry — ModuleRegistry class."""

from app.plugins.registry import ModuleRegistry
from app.plugins.types import BackendModule
from app.core.connectors import ToolConnector


def _make_module(name="mod1", enabled=True, connectors=None, scan_parsers=None):
    return BackendModule(
        name=name,
        version="1.0.0",
        title=name,
        description="test",
        enabled=enabled,
        connectors=connectors or [],
        scan_parsers=scan_parsers or {},
    )


class TestModuleRegistryRegister:
    def test_register_and_get(self):
        reg = ModuleRegistry()
        mod = _make_module("test")
        reg.register(mod)
        assert reg.get("test") is mod

    def test_overwrite_existing(self):
        reg = ModuleRegistry()
        mod1 = _make_module("test", enabled=True)
        mod2 = _make_module("test", enabled=False)
        reg.register(mod1)
        reg.register(mod2)
        assert reg.get("test") is mod2


class TestModuleRegistryGetAll:
    def test_returns_all(self):
        reg = ModuleRegistry()
        reg.register(_make_module("a"))
        reg.register(_make_module("b"))
        all_mods = reg.get_all()
        assert len(all_mods) == 2

    def test_empty(self):
        reg = ModuleRegistry()
        assert reg.get_all() == []


class TestModuleRegistryGetEnabled:
    def test_filters_disabled(self):
        reg = ModuleRegistry()
        reg.register(_make_module("enabled", enabled=True))
        reg.register(_make_module("disabled", enabled=False))
        enabled = reg.get_enabled()
        assert len(enabled) == 1
        assert enabled[0].name == "enabled"


class TestModuleRegistryGet:
    def test_found(self):
        reg = ModuleRegistry()
        mod = _make_module("test")
        reg.register(mod)
        assert reg.get("test") is mod

    def test_not_found(self):
        reg = ModuleRegistry()
        assert reg.get("nonexistent") is None


class TestModuleRegistryGetScanParser:
    def test_finds_parser(self):
        reg = ModuleRegistry()
        parser = lambda x: x
        reg.register(_make_module("m1", scan_parsers={"nmap": parser}))
        found = reg.get_scan_parser("nmap")
        assert found is parser

    def test_skips_disabled(self):
        reg = ModuleRegistry()
        parser = lambda x: x
        reg.register(_make_module("m1", enabled=False, scan_parsers={"nmap": parser}))
        assert reg.get_scan_parser("nmap") is None

    def test_not_found(self):
        reg = ModuleRegistry()
        reg.register(_make_module("m1", scan_parsers={"nmap": lambda x: x}))
        assert reg.get_scan_parser("xml") is None


class TestModuleRegistryListScanParsers:
    def test_lists_parsers(self):
        reg = ModuleRegistry()
        reg.register(_make_module("m1", scan_parsers={"nmap": lambda x: x, "nessus": lambda x: x}))
        reg.register(_make_module("m2", scan_parsers={"nmap": lambda x: x}))
        parsers = reg.list_scan_parsers()
        assert "nmap" in parsers
        assert "nessus" in parsers
        assert len(parsers) == 2

    def test_empty(self):
        reg = ModuleRegistry()
        assert reg.list_scan_parsers() == []


class TestModuleRegistryGetConnector:
    def test_finds_connector(self):
        reg = ModuleRegistry()
        tc = ToolConnector(key="nmap", title="Nmap", category="scan")
        reg.register(_make_module("m1", connectors=[tc]))
        found = reg.get_connector("nmap")
        assert found is tc

    def test_skips_disabled(self):
        reg = ModuleRegistry()
        tc = ToolConnector(key="nmap", title="Nmap", category="scan", enabled=False)
        reg.register(_make_module("m1", connectors=[tc]))
        assert reg.get_connector("nmap") is None

    def test_not_found(self):
        reg = ModuleRegistry()
        reg.register(_make_module("m1"))
        assert reg.get_connector("nope") is None


class TestModuleRegistryListConnectors:
    def test_lists_all(self):
        reg = ModuleRegistry()
        tc1 = ToolConnector(key="nmap", title="Nmap", category="scan")
        tc2 = ToolConnector(key="nuclei", title="Nuclei", category="scan")
        reg.register(_make_module("m1", connectors=[tc1, tc2]))
        connectors = reg.list_connectors()
        assert len(connectors) == 2

    def test_includes_module_name(self):
        reg = ModuleRegistry()
        tc = ToolConnector(key="nmap", title="Nmap", category="scan")
        reg.register(_make_module("mymod", connectors=[tc]))
        connectors = reg.list_connectors()
        assert connectors[0]["module"] == "mymod"

    def test_sorted_by_category_and_title(self):
        reg = ModuleRegistry()
        tc1 = ToolConnector(key="b", title="B Tool", category="scan")
        tc2 = ToolConnector(key="a", title="A Tool", category="scan")
        tc3 = ToolConnector(key="c", title="C Tool", category="exec")
        reg.register(_make_module("m", connectors=[tc1, tc2, tc3]))
        connectors = reg.list_connectors()
        assert connectors[0]["category"] == "exec"
        assert connectors[1]["key"] == "a"
        assert connectors[2]["key"] == "b"
