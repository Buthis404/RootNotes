"""Extended tests for import_bloodhound — trust edges and ACL paths."""
import io
import json
import zipfile
import pytest
from unittest.mock import MagicMock, patch

from app.routers.import_bloodhound import (
    _host_short,
    _user_short,
    _get_items,
    _bh_trust_type_dir,
    _bh_add_edge,
    _add_host_tag,
    _bh_dc_or_tag,
    _bh_build_index,
)


class TestHostShort:
    def test_fqdn(self):
        assert _host_short("SDOTSON.EDU.STF") == "SDOTSON"

    def test_single(self):
        assert _host_short("PC1") == "PC1"

    def test_empty(self):
        assert _host_short("") == ""


class TestUserShort:
    def test_upn(self):
        assert _user_short("S_DOTSON@EDU.STF") == "s_dotson"

    def test_plain(self):
        assert _user_short("admin") == "admin"

    def test_empty(self):
        assert _user_short("") == ""


class TestGetItems:
    def test_data_key(self):
        assert _get_items({"data": [{"id": 1}]}) == [{"id": 1}]

    def test_computers_key(self):
        assert _get_items({"computers": [{"id": 2}]}) == [{"id": 2}]

    def test_users_key(self):
        assert _get_items({"users": [{"id": 3}]}) == [{"id": 3}]

    def test_groups_key(self):
        assert _get_items({"groups": [{"id": 4}]}) == [{"id": 4}]

    def test_sessions_key(self):
        assert _get_items({"sessions": [{"id": 5}]}) == [{"id": 5}]

    def test_no_match(self):
        assert _get_items({}) == []


class TestBhTrustTypeDir:
    def test_types(self):
        t, d = _bh_trust_type_dir({"TrustType": 0, "TrustDirection": 3})
        assert t == "ParentChild"
        assert d == "Bidirectional"

    def test_string_values(self):
        t, d = _bh_trust_type_dir({"TrustType": "Custom", "TrustDirection": "Outbound"})
        assert t == "Custom"
        assert d == "Outbound"


class TestBhAddEdge:
    def test_basic(self):
        edges = []
        seen = set()
        result = _bh_add_edge(seen, edges, "h1", "h2", "ssh", "SSH")
        assert result is True
        assert len(edges) == 1

    def test_duplicate(self):
        edges = []
        seen = set()
        _bh_add_edge(seen, edges, "h1", "h2", "ssh", "SSH")
        result = _bh_add_edge(seen, edges, "h1", "h2", "ssh", "SSH")
        assert result is False

    def test_self_edge(self):
        edges = []
        seen = set()
        result = _bh_add_edge(seen, edges, "h1", "h1", "ssh", "SSH")
        assert result is False

    def test_empty_ids(self):
        edges = []
        seen = set()
        result = _bh_add_edge(seen, edges, "", "h2", "ssh", "SSH")
        assert result is False


class TestAddHostTag:
    def test_new_tag(self):
        host = MagicMock()
        host.tags = ["existing"]
        result = _add_host_tag(host, "new_tag")
        assert result is True
        assert "new_tag" in host.tags

    def test_existing_tag(self):
        host = MagicMock()
        host.tags = ["existing"]
        result = _add_host_tag(host, "existing")
        assert result is False


class TestBhDcOrTag:
    def test_dc_role(self):
        h = MagicMock()
        h.role = "domain_controller"
        h.tags = []
        assert _bh_dc_or_tag(h) is True

    def test_dc_tag(self):
        h = MagicMock()
        h.role = ""
        h.tags = ["dc"]
        assert _bh_dc_or_tag(h) is True

    def test_not_dc(self):
        h = MagicMock()
        h.role = "server"
        h.tags = ["web"]
        assert _bh_dc_or_tag(h) is False


class TestBhBuildIndex:
    def test_basic(self):
        h1 = MagicMock()
        h1.hostname = "PC1"
        h2 = MagicMock()
        h2.hostname = "PC2"
        c1 = MagicMock()
        c1.username = "admin"
        c1.service = "AD"
        hn, cr = _bh_build_index([h1, h2], [c1])
        assert "PC1" in hn
        assert "admin" in cr
