import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
from fastapi import HTTPException

from app.core.utils import (
    ensure_under_upload_root,
    split_scope_values,
    infer_scope_type,
    is_project_network_value,
    safe_upload_name,
    norm_text,
    normalize_domain,
    domain_short_label,
    domains_match,
    stable_edge_id,
    new_id,
    ts_now,
    utcnow,
)


class TestEnsureUnderUploadRoot:
    def test_valid(self, tmp_path, monkeypatch):
        monkeypatch.setattr("app.core.utils.UPLOAD_ROOT", tmp_path)
        f = tmp_path / "test.txt"
        f.write_text("x")
        r = ensure_under_upload_root(f)
        assert r == f.resolve()

    def test_invalid(self, tmp_path, monkeypatch):
        monkeypatch.setattr("app.core.utils.UPLOAD_ROOT", tmp_path / "uploads")
        (tmp_path / "uploads").mkdir()
        f = tmp_path / "other" / "evil.txt"
        with pytest.raises(HTTPException) as exc_info:
            ensure_under_upload_root(f)
        assert exc_info.value.status_code == 400


class TestSplitScopeValues:
    def test_comma(self):
        assert split_scope_values("a, b, c") == ["a", "b", "c"]

    def test_newline(self):
        assert split_scope_values("a\nb\nc") == ["a", "b", "c"]

    def test_semicolon(self):
        assert split_scope_values("a;b;c") == ["a", "b", "c"]

    def test_duplicates(self):
        assert split_scope_values("a,a,b") == ["a", "b"]

    def test_empty(self):
        assert split_scope_values("") == []

    def test_whitespace(self):
        assert split_scope_values("  a  ,  b  ") == ["a", "b"]


class TestInferScopeType:
    def test_url(self):
        assert infer_scope_type("http://example.com") == "url"
        assert infer_scope_type("https://example.com") == "url"

    def test_cidr(self):
        assert infer_scope_type("10.0.0.0/24") == "cidr"

    def test_ip(self):
        assert infer_scope_type("10.0.0.1") == "cidr"

    def test_domain(self):
        assert infer_scope_type("example.local") == "domain"
        assert infer_scope_type("example.corp") == "domain"
        assert infer_scope_type("example.lan") == "domain"

    def test_hostname_with_dots(self):
        r = infer_scope_type("example.com")
        assert r in ("domain", "hostname")

    def test_hostname(self):
        assert infer_scope_type("server01") == "hostname"

    def test_empty(self):
        assert infer_scope_type("") == "hostname"


class TestIsProjectNetworkValue:
    def test_cidr(self):
        assert is_project_network_value("10.0.0.0/24") is True

    def test_ip(self):
        assert is_project_network_value("10.0.0.1") is True

    def test_domain(self):
        assert is_project_network_value("example.com") is False

    def test_empty(self):
        assert is_project_network_value("") is False


class TestSafeUploadName:
    def test_basic(self):
        assert safe_upload_name("hello.txt") == "hello.txt"

    def test_path_traversal(self):
        r = safe_upload_name("../../etc/passwd")
        assert ".." not in r

    def test_empty(self):
        r = safe_upload_name("")
        assert isinstance(r, str)


class TestNormText:
    def test_basic(self):
        assert norm_text("  hello  world  ") == "hello world"

    def test_none(self):
        assert norm_text(None) == ""

    def test_empty(self):
        assert norm_text("") == ""


class TestNormalizeDomain:
    def test_basic(self):
        assert normalize_domain("Example.COM") == "example.com"

    def test_empty(self):
        assert normalize_domain("") == ""


class TestDomainShortLabel:
    def test_basic(self):
        r = domain_short_label("sub.example.com")
        assert isinstance(r, str)


class TestDomainsMatch:
    def test_match(self):
        assert domains_match("Example.COM", "example.com") is True

    def test_no_match(self):
        assert domains_match("a.com", "b.com") is False


class TestStableEdgeId:
    def test_deterministic(self):
        r1 = stable_edge_id("n1", "n2", "auto")
        r2 = stable_edge_id("n1", "n2", "auto")
        assert r1 == r2

    def test_different_order_different(self):
        r1 = stable_edge_id("a", "b", "auto")
        r2 = stable_edge_id("b", "a", "auto")
        assert r1 != r2

    def test_different_source(self):
        r1 = stable_edge_id("a", "b", "auto")
        r2 = stable_edge_id("a", "b", "manual")
        assert r1 != r2


class TestNewId:
    def test_prefix(self):
        r = new_id("tst")
        assert r.startswith("tst")

    def test_unique(self):
        assert new_id("a") != new_id("a")


class TestTimestamps:
    def test_ts_now(self):
        r = ts_now()
        assert isinstance(r, str)
        assert len(r) > 0

    def test_utcnow(self):
        r = utcnow()
        assert r is not None
