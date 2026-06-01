"""Unit tests for app.core.utils public functions (excluding domain helpers covered by test_domain_utils)."""
import hashlib
import re
import time

from app.core.utils import (
    new_id,
    stable_edge_id,
    ts_now,
    utcnow,
    norm_text,
    safe_upload_name,
    split_scope_values,
    is_project_network_value,
)


class TestNewId:
    def test_has_prefix(self):
        assert new_id("hst").startswith("hst")

    def test_length(self):
        assert len(new_id("x")) == 9

    def test_unique(self):
        ids = {new_id("a") for _ in range(100)}
        assert len(ids) == 100

    def test_empty_prefix(self):
        result = new_id("")
        assert len(result) == 8


class TestStableEdgeId:
    def test_deterministic(self):
        a = stable_edge_id("n1", "n2", "src", "kind")
        b = stable_edge_id("n1", "n2", "src", "kind")
        assert a == b

    def test_starts_with_edg(self):
        assert stable_edge_id("a", "b", "c").startswith("edg")

    def test_length(self):
        result = stable_edge_id("a", "b", "c", "d")
        assert len(result) == 15

    def test_different_inputs_different_ids(self):
        a = stable_edge_id("n1", "n2", "s1")
        b = stable_edge_id("n1", "n2", "s2")
        assert a != b

    def test_kind_matters(self):
        a = stable_edge_id("a", "b", "s", "k1")
        b = stable_edge_id("a", "b", "s", "k2")
        assert a != b

    def test_none_inputs(self):
        result = stable_edge_id(None, None, None, None)
        assert result.startswith("edg")
        raw = "|||".encode()
        expected = "edg" + hashlib.sha256(raw).hexdigest()[:12]
        assert result == expected

    def test_empty_strings(self):
        result = stable_edge_id("", "", "", "")
        raw = "|||".encode()
        expected = "edg" + hashlib.sha256(raw).hexdigest()[:12]
        assert result == expected

    def test_order_matters(self):
        a = stable_edge_id("n1", "n2", "s")
        b = stable_edge_id("n2", "n1", "s")
        assert a != b


class TestTsNow:
    def test_format(self):
        ts = ts_now()
        assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", ts)

    def test_ends_with_z(self):
        assert ts_now().endswith("Z")

    def test_returns_string(self):
        assert isinstance(ts_now(), str)


class TestUtcnow:
    def test_naive(self):
        dt = utcnow()
        assert dt.tzinfo is None

    def test_recent(self):
        dt = utcnow()
        diff = time.time() - dt.timestamp()
        assert abs(diff) < 2

    def test_returns_datetime(self):
        from datetime import datetime
        assert isinstance(utcnow(), datetime)


class TestNormText:
    def test_basic(self):
        assert norm_text("  Hello   World  ") == "hello world"

    def test_none(self):
        assert norm_text(None) == ""

    def test_empty(self):
        assert norm_text("") == ""

    def test_tabs_and_newlines(self):
        assert norm_text("hello\tworld\nfoo") == "hello world foo"

    def test_multiple_spaces(self):
        assert norm_text("a   b    c") == "a b c"


class TestSafeUploadName:
    def test_normal_name(self):
        assert safe_upload_name("report.pdf") == "report.pdf"

    def test_strips_path(self):
        assert safe_upload_name("/etc/passwd") == "passwd"

    def test_strips_path_backslash(self):
        result = safe_upload_name("C:\\Users\\admin\\file.txt")
        assert "\\" not in result

    def test_none_gives_default(self):
        assert safe_upload_name(None) == "attachment.bin"

    def test_empty_gives_default(self):
        assert safe_upload_name("") == "attachment.bin"

    def test_dangerous_chars_replaced(self):
        result = safe_upload_name("file<>:|?*.txt")
        assert "<" not in result
        assert ">" not in result

    def test_strips_leading_dots(self):
        result = safe_upload_name(".hidden")
        assert not result.startswith(".")

    def test_only_dots_gives_default(self):
        assert safe_upload_name("...") == "attachment.bin"


class TestSplitScopeValues:
    def test_comma_separated(self):
        assert split_scope_values("a, b, c") == ["a", "b", "c"]

    def test_newline_separated(self):
        assert split_scope_values("a\nb\nc") == ["a", "b", "c"]

    def test_semicolon_separated(self):
        assert split_scope_values("a;b;c") == ["a", "b", "c"]

    def test_mixed_separators(self):
        assert split_scope_values("a, b\nc;d") == ["a", "b", "c", "d"]

    def test_deduplication(self):
        assert split_scope_values("a, a, b, a") == ["a", "b"]

    def test_empty_string(self):
        assert split_scope_values("") == []

    def test_none(self):
        assert split_scope_values(None) == []

    def test_strips_whitespace(self):
        assert split_scope_values("  a  ,  b  ") == ["a", "b"]

    def test_skips_empty_parts(self):
        assert split_scope_values("a,,b,") == ["a", "b"]


class TestIsProjectNetworkValue:
    def test_ip(self):
        assert is_project_network_value("10.0.0.1")

    def test_cidr(self):
        assert is_project_network_value("10.0.0.0/24")

    def test_domain(self):
        assert not is_project_network_value("corp.local")

    def test_empty(self):
        assert not is_project_network_value("")

    def test_none_like(self):
        assert not is_project_network_value(None)

    def test_hostname(self):
        assert not is_project_network_value("dc01")

    def test_non_ip_pattern(self):
        assert not is_project_network_value("abc.def.ghi.jkl")
