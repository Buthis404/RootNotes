"""Tests for app.core.connectors — ToolConnector dataclass."""

from app.core.connectors import ToolConnector


class TestToolConnector:
    def test_to_dict(self):
        tc = ToolConnector(
            key="nmap",
            title="Nmap",
            category="scan",
            description="Network scanner",
            supported_operations=["scan"],
            supported_sources=["xml"],
            creates_entities=["host"],
            execution_mode="sync",
            enabled=True,
        )
        d = tc.to_dict()
        assert d["key"] == "nmap"
        assert d["title"] == "Nmap"
        assert d["category"] == "scan"
        assert d["description"] == "Network scanner"
        assert d["supported_operations"] == ["scan"]
        assert d["enabled"] is True

    def test_defaults(self):
        tc = ToolConnector(key="k", title="T", category="cat")
        d = tc.to_dict()
        assert d["supported_operations"] == []
        assert d["supported_sources"] == []
        assert d["creates_entities"] == []
        assert d["execution_mode"] == "sync"
        assert d["enabled"] is True
        assert d["description"] == ""

    def test_to_dict_copies_lists(self):
        tc = ToolConnector(key="k", title="T", category="cat", supported_operations=["a"])
        d = tc.to_dict()
        d["supported_operations"].append("b")
        assert tc.supported_operations == ["a"]

    def test_disabled_connector(self):
        tc = ToolConnector(key="k", title="T", category="cat", enabled=False)
        assert tc.to_dict()["enabled"] is False

    def test_async_execution_mode(self):
        tc = ToolConnector(key="k", title="T", category="cat", execution_mode="async")
        assert tc.to_dict()["execution_mode"] == "async"
