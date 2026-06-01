import pytest
from unittest.mock import MagicMock

from app.routers.search import (
    _parse_query,
    _FILTER_KEYS,
    _host_snippet,
    _host_related,
    _ilike,
)


class TestParseQuery:
    def test_plain_text(self):
        text, filters = _parse_query("hello world")
        assert text == "hello world"
        assert filters == {}

    def test_filter(self):
        text, filters = _parse_query("type:cred admin")
        assert text == "admin"
        assert filters["type"] == "cred"

    def test_multiple_filters(self):
        text, filters = _parse_query("type:cred severity:high password")
        assert text == "password"
        assert filters["type"] == "cred"
        assert filters["severity"] == "high"

    def test_invalid_filter_key(self):
        text, filters = _parse_query("invalid:value test")
        assert text == "invalid:value test"
        assert filters == {}

    def test_empty_value(self):
        text, filters = _parse_query("type: test")
        assert text == "type: test"

    def test_all_filter_keys(self):
        for key in _FILTER_KEYS:
            text, filters = _parse_query(f"{key}:val")
            assert filters.get(key) == "val"

    def test_empty_query(self):
        text, filters = _parse_query("")
        assert text == ""
        assert filters == {}


class TestHostSnippet:
    def test_with_os_and_role(self):
        h = MagicMock()
        h.os = "Linux"
        h.role = "server"
        r = _host_snippet(h)
        assert "Linux" in r
        assert "server" in r

    def test_os_only(self):
        h = MagicMock()
        h.os = "Windows"
        h.role = None
        r = _host_snippet(h)
        assert "Windows" in r

    def test_empty(self):
        h = MagicMock()
        h.os = None
        h.role = None
        r = _host_snippet(h)
        assert r == ""


class TestHostRelated:
    def test_basic(self):
        db = MagicMock()
        cred = MagicMock()
        cred.id = "crd1"
        cred.username = "admin"
        cred.service = "smb"
        finding = MagicMock()
        finding.id = "fnd1"
        finding.title = "vuln"
        finding.severity = "high"
        db.query.return_value.filter.return_value.limit.return_value.all.side_effect = [
            [cred], [finding]
        ]
        h = MagicMock()
        h.pid = "p1"
        h.ip = "10.0.0.1"
        h.id = "h1"
        r = _host_related(h, db)
        assert len(r) == 2
        assert r[0]["type"] == "cred"
        assert r[1]["type"] == "finding"

    def test_empty(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.limit.return_value.all.return_value = []
        h = MagicMock()
        h.pid = "p1"
        h.ip = "10.0.0.1"
        h.id = "h1"
        r = _host_related(h, db)
        assert r == []


class TestIlike:
    def test_basic(self):
        assert _ilike("test") == "%test%"
