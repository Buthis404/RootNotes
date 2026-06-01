import pytest
import json
import io
import zipfile
from unittest.mock import MagicMock, patch

from app.routers.import_bloodhound import (
    _host_short,
    _user_short,
    _get_items,
    _add_host_tag,
    _bh_add_edge,
    _bh_dc_or_tag,
    _bh_build_index,
    _bh_trust_type_dir,
    parse_bloodhound_json,
    _bh_process_groups,
    _ACL_EDGE_MAP,
    _DA_GROUP_NAMES,
)


class TestHostShort:
    def test_fqdn(self):
        assert _host_short("SDOTSON.EDU.STF") == "SDOTSON"

    def test_single(self):
        assert _host_short("SERVER") == "SERVER"

    def test_empty(self):
        assert _host_short("") == ""


class TestUserShort:
    def test_email(self):
        assert _user_short("S_DOTSON@EDU.STF") == "s_dotson"

    def test_plain(self):
        assert _user_short("admin") == "admin"

    def test_empty(self):
        assert _user_short("") == ""


class TestGetItems:
    def test_data_key(self):
        assert _get_items({"data": [1, 2]}) == [1, 2]

    def test_computers_key(self):
        assert _get_items({"computers": [{"id": "c1"}]}) == [{"id": "c1"}]

    def test_empty(self):
        assert _get_items({}) == []


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


class TestBhAddEdge:
    def test_basic(self):
        seen = set()
        edges = []
        result = _bh_add_edge(seen, edges, "h1", "h2", "ssh", "SSH Access")
        assert result is True
        assert len(edges) == 1

    def test_dedupe(self):
        seen = set()
        edges = []
        _bh_add_edge(seen, edges, "h1", "h2", "ssh", "SSH")
        result = _bh_add_edge(seen, edges, "h1", "h2", "ssh", "SSH")
        assert result is False

    def test_self_link(self):
        seen = set()
        edges = []
        result = _bh_add_edge(seen, edges, "h1", "h1", "ssh", "SSH")
        assert result is False

    def test_empty_ids(self):
        seen = set()
        edges = []
        assert _bh_add_edge(seen, edges, "", "h2", "ssh", "SSH") is False
        assert _bh_add_edge(seen, edges, "h1", "", "ssh", "SSH") is False


class TestBhDcOrTag:
    def test_role(self):
        host = MagicMock()
        host.role = "domain_controller"
        host.tags = []
        assert _bh_dc_or_tag(host) is True

    def test_tag(self):
        host = MagicMock()
        host.role = ""
        host.tags = ["DC"]
        assert _bh_dc_or_tag(host) is True

    def test_no(self):
        host = MagicMock()
        host.role = "server"
        host.tags = []
        assert _bh_dc_or_tag(host) is False


class TestBhBuildIndex:
    def test_basic(self):
        h = MagicMock()
        h.hostname = "SRV1"
        c = MagicMock()
        c.username = "admin"
        c.service = "AD"
        host_idx, cred_idx = _bh_build_index([h], [c])
        assert "SRV1" in host_idx
        assert "admin" in cred_idx


class TestBhTrustTypeDir:
    def test_parent_child(self):
        t, d = _bh_trust_type_dir({"TrustType": 0, "TrustDirection": 3})
        assert t == "ParentChild"
        assert d == "Bidirectional"

    def test_non_int(self):
        t, d = _bh_trust_type_dir({"TrustType": "Custom", "TrustDirection": "Inbound"})
        assert t == "Custom"
        assert d == "Inbound"


class TestBhProcessGroups:
    def test_da_detection(self):
        groups_raw = [
            {"Properties": {"name": "Domain Admins", "objectid": "S-1-5-21-512"}, "Members": [{"ObjectIdentifier": "S-1-5-21-user1"}]},
        ]
        da_sids = set()
        domain = _bh_process_groups(groups_raw, {}, da_sids, "")
        assert "S-1-5-21-user1" in da_sids

    def test_well_known_rid(self):
        groups_raw = [
            {"Properties": {"name": "Some Group", "objectid": "S-1-5-21-512"}, "Members": [{"ObjectIdentifier": "S-1-5-21-user1"}]},
        ]
        da_sids = set()
        _bh_process_groups(groups_raw, {}, da_sids, "")
        assert "S-1-5-21-user1" in da_sids


class TestParseBloodhoundJson:
    def test_invalid_json(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            parse_bloodhound_json("p1", "computers", b"not json", MagicMock())


class TestAclEdgeMap:
    def test_contains_expected(self):
        assert "genericall" in _ACL_EDGE_MAP
        assert "dcsyncrights" in _ACL_EDGE_MAP
