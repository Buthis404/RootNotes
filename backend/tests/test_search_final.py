import pytest
from unittest.mock import MagicMock, patch

from app.routers.search import (
    _parse_query,
    _allowed_pids,
    _scope,
    _ilike,
    _host_snippet,
    _cred_snippet,
    _loot_snippet,
    _type_match,
    _rank_key,
    _findings_meta,
)


class TestParseQuery:
    def test_plain_text(self):
        text, filters = _parse_query("hello world")
        assert text == "hello world"
        assert filters == {}

    def test_type_filter(self):
        text, filters = _parse_query("type:host query")
        assert filters.get("type") == "host"

    def test_severity_filter(self):
        text, filters = _parse_query("severity:high test")
        assert filters.get("severity") == "high"

    def test_status_filter(self):
        text, filters = _parse_query("status:open term")
        assert filters.get("status") == "open"

    def test_tag_filter(self):
        text, filters = _parse_query("tag:nmap search")
        assert filters.get("tag") == "nmap"

    def test_unknown_key_not_filter(self):
        text, filters = _parse_query("foo:bar term")
        assert "foo" not in filters
        assert "foo:bar" in text or "term" in text

    def test_empty_value(self):
        text, filters = _parse_query("type: term")
        assert "type" not in filters

    def test_all_filters(self):
        text, filters = _parse_query("type:host severity:high status:open service:smb role:dc source:nmap connector:nmap tag:cme")
        assert len(filters) >= 5


class TestAllowedPids:
    def test_with_pid(self):
        user = MagicMock()
        with patch("app.routers.search.check_pid_access"):
            result = _allowed_pids(MagicMock(), user, "p1")
            assert result == ["p1"]

    def test_admin_no_pid(self):
        user = MagicMock()
        with patch("app.routers.search.is_admin", return_value=True):
            result = _allowed_pids(MagicMock(), user, "")
            assert result is None


class TestScope:
    def test_pid_exact(self):
        q = MagicMock()
        result = _scope(q, MagicMock(), None, "p1")
        q.filter.assert_called_once()

    def test_pid_list(self):
        q = MagicMock()
        result = _scope(q, MagicMock(), ["p1", "p2"], "")
        q.filter.assert_called_once()

    def test_no_filter(self):
        q = MagicMock()
        result = _scope(q, MagicMock(), None, "")
        assert result == q


class TestIlike:
    def test_basic(self):
        assert _ilike("test") == "%test%"


class TestHostSnippet:
    def test_with_role(self):
        h = MagicMock()
        h.os = "Windows"
        h.role = "server"
        assert "Windows" in _host_snippet(h)
        assert "server" in _host_snippet(h)

    def test_no_role(self):
        h = MagicMock()
        h.os = "Linux"
        h.role = None
        assert "Linux" in _host_snippet(h)


class TestCredSnippet:
    def test_basic(self):
        c = MagicMock()
        c.service = "smb"
        c.cracked = False
        assert "smb" in _cred_snippet(c)

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
        assert "file" in _loot_snippet(loot)

    def test_with_artifact(self):
        loot = MagicMock()
        loot.loot_type = "file"
        loot.artifact_type = "screenshot"
        assert "screenshot" in _loot_snippet(loot)


class TestTypeMatch:
    def test_no_filter(self):
        assert _type_match("", ("host",)) is True

    def test_match(self):
        assert _type_match("host", ("host", "hosts")) is True

    def test_no_match(self):
        assert _type_match("cred", ("host",)) is False


class TestRankKey:
    def test_basic(self):
        assert _rank_key({"_rank": 0.5}) == 0.5


class TestFindingsMeta:
    def test_basic(self):
        f = MagicMock()
        f.severity = "high"
        f.status = "open"
        f.source = "nmap"
        result = _findings_meta(f)
        assert result["severity"] == "high"
