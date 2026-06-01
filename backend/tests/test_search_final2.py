import pytest
from unittest.mock import MagicMock

from app.routers.search import (
    _parse_query,
    _type_match,
    _rank_key,
    _host_snippet,
    _cred_snippet,
    _loot_snippet,
    _findings_meta,
    _FILTER_KEYS,
)


class TestParseQuery:
    def test_basic(self):
        text, filters = _parse_query("hello world")
        assert text == "hello world"
        assert filters == {}

    def test_type_filter(self):
        text, filters = _parse_query("type:host query")
        assert filters["type"] == "host"
        assert "query" in text

    def test_severity_filter(self):
        text, filters = _parse_query("severity:high ssh")
        assert filters["severity"] == "high"

    def test_status_filter(self):
        text, filters = _parse_query("status:open")
        assert filters["status"] == "open"

    def test_service_filter(self):
        text, filters = _parse_query("service:smb")
        assert filters["service"] == "smb"

    def test_role_filter(self):
        text, filters = _parse_query("role:server")
        assert filters["role"] == "server"

    def test_source_filter(self):
        text, filters = _parse_query("source:nmap")
        assert filters["source"] == "nmap"

    def test_connector_filter(self):
        text, filters = _parse_query("connector:nmap")
        assert filters["connector"] == "nmap"

    def test_tag_filter(self):
        text, filters = _parse_query("tag:dc")
        assert filters["tag"] == "dc"

    def test_unknown_filter_key(self):
        text, filters = _parse_query("foo:bar query")
        assert "foo:bar" in text
        assert filters == {}

    def test_empty_value(self):
        text, filters = _parse_query("type: query")
        assert filters == {}

    def test_all_filters(self):
        for key in _FILTER_KEYS:
            _, f = _parse_query(f"{key}:val")
            assert key in f


class TestTypeMatch:
    def test_empty(self):
        assert _type_match("", ("host",)) is True

    def test_match(self):
        assert _type_match("host", ("host", "hosts")) is True

    def test_no_match(self):
        assert _type_match("cred", ("host",)) is False


class TestRankKey:
    def test_basic(self):
        assert _rank_key({"_rank": 0.5}) == 0.5
        assert _rank_key({"_rank": 1.0}) == 1.0


class TestHostSnippet:
    def test_with_role(self):
        h = MagicMock()
        h.os = "Linux"
        h.role = "server"
        assert "Linux" in _host_snippet(h)
        assert "server" in _host_snippet(h)

    def test_no_role(self):
        h = MagicMock()
        h.os = "Windows"
        h.role = ""
        assert "Windows" in _host_snippet(h)
        assert "•" not in _host_snippet(h)


class TestCredSnippet:
    def test_basic(self):
        c = MagicMock()
        c.service = "smb"
        c.cracked = False
        assert "smb" in _cred_snippet(c)
        assert "cracked" not in _cred_snippet(c)

    def test_cracked(self):
        c = MagicMock()
        c.service = "ssh"
        c.cracked = True
        assert "cracked" in _cred_snippet(c)


class TestLootSnippet:
    def test_basic(self):
        loot = MagicMock()
        loot.loot_type = "file"
        loot.artifact_type = None
        assert _loot_snippet(loot) == "file"

    def test_with_artifact(self):
        loot = MagicMock()
        loot.loot_type = "file"
        loot.artifact_type = "screenshot"
        assert "screenshot" in _loot_snippet(loot)


class TestFindingsMeta:
    def test_basic(self):
        f = MagicMock()
        f.severity = "high"
        f.status = "open"
        f.source = "nmap"
        r = _findings_meta(f)
        assert r["severity"] == "high"
        assert r["status"] == "open"
        assert r["source"] == "nmap"
