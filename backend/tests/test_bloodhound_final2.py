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
    _bh_process_domain_trusts,
    _bh_process_ace,
    parse_bloodhound_json,
    _DA_GROUP_NAMES,
    _ACL_EDGE_MAP,
)


class TestHostShort:
    def test_fqdn(self):
        assert _host_short("SRV01.CORP.LOCAL") == "SRV01"

    def test_empty(self):
        assert _host_short("") == ""


class TestUserShort:
    def test_upn(self):
        assert _user_short("ADMIN@CORP.LOCAL") == "admin"

    def test_plain(self):
        assert _user_short("admin") == "admin"


class TestGetItems:
    def test_data_key(self):
        assert _get_items({"data": [1, 2]}) == [1, 2]

    def test_computers_key(self):
        assert _get_items({"computers": [1]}) == [1]

    def test_empty(self):
        assert _get_items({}) == []


class TestAddHostTag:
    def test_new_tag(self):
        host = MagicMock()
        host.tags = ["existing"]
        assert _add_host_tag(host, "new") is True
        assert "new" in host.tags

    def test_duplicate_tag(self):
        host = MagicMock()
        host.tags = ["existing"]
        assert _add_host_tag(host, "existing") is False


class TestBhAddEdge:
    def test_basic(self):
        seen = set()
        edges = []
        assert _bh_add_edge(seen, edges, "h1", "h2", "smb", "admin") is True
        assert len(edges) == 1
        assert edges[0]["from_host_id"] == "h1"

    def test_same_ids(self):
        seen = set()
        edges = []
        assert _bh_add_edge(seen, edges, "h1", "h1", "smb", "admin") is False

    def test_empty_ids(self):
        seen = set()
        edges = []
        assert _bh_add_edge(seen, edges, "", "h2", "smb", "admin") is False
        assert _bh_add_edge(seen, edges, "h1", "", "smb", "admin") is False

    def test_duplicate(self):
        seen = set()
        edges = []
        _bh_add_edge(seen, edges, "h1", "h2", "smb", "admin")
        assert _bh_add_edge(seen, edges, "h1", "h2", "smb", "admin") is False


class TestBhDcOrTag:
    def test_role(self):
        h = MagicMock()
        h.role = "domain_controller"
        h.tags = []
        assert _bh_dc_or_tag(h) is True

    def test_tag(self):
        h = MagicMock()
        h.role = ""
        h.tags = ["DC"]
        assert _bh_dc_or_tag(h) is True

    def test_no(self):
        h = MagicMock()
        h.role = "server"
        h.tags = []
        assert _bh_dc_or_tag(h) is False


class TestBhBuildIndex:
    def test_basic(self):
        h1 = MagicMock()
        h1.hostname = "SRV01"
        h2 = MagicMock()
        h2.hostname = ""
        c1 = MagicMock()
        c1.username = "admin"
        c1.service = "os"
        c2 = MagicMock()
        c2.username = "admin"
        c2.service = "smb"
        h_by_hn, c_by_un = _bh_build_index([h1, h2], [c1, c2])
        assert "SRV01" in h_by_hn
        assert "admin" in c_by_un
        assert c_by_un["admin"].service == "os"


class TestBhTrustTypeDir:
    def test_parent_child(self):
        t, d = _bh_trust_type_dir({"TrustType": 0, "TrustDirection": 3})
        assert t == "ParentChild"
        assert d == "Bidirectional"

    def test_string_type(self):
        t, d = _bh_trust_type_dir({"TrustType": "Custom", "TrustDirection": "Inbound"})
        assert t == "Custom"
        assert d == "Inbound"

    def test_none(self):
        t, d = _bh_trust_type_dir({"TrustType": None, "TrustDirection": None})
        assert t == "Unknown"
        assert d == "Bidirectional"


class TestBhProcessDomainTrusts:
    def test_basic(self):
        dc_hids = {"corp.local": ["h1"], "child.corp.local": ["h2"]}
        seen = set()
        edges = []
        stats = {"trust_edges": 0}
        dom = {"Properties": {"name": "CORP.LOCAL", "domain": ""},
               "Trusts": [{"TargetDomainName": "child.corp.local", "TrustType": 0, "TrustDirection": 3}]}
        _bh_process_domain_trusts(dom, dc_hids, seen, edges, stats)
        assert stats["trust_edges"] == 1

    def test_skip_same_domain(self):
        dc_hids = {"corp.local": ["h1"]}
        stats = {"trust_edges": 0}
        dom = {"Properties": {"name": "corp.local"},
               "Trusts": [{"TargetDomainName": "corp.local", "TrustType": 0, "TrustDirection": 3}]}
        _bh_process_domain_trusts(dom, dc_hids, set(), [], stats)
        assert stats["trust_edges"] == 0


class TestBhProcessAce:
    def test_known_right(self):
        seen = set()
        edges = []
        stats = {"acl_edges": 0}
        db = MagicMock()
        ace = {"RightName": "GenericAll", "PrincipalSID": "s1"}
        sid_to_hid = {"s1": "h1"}
        sid_to_cid = {}
        _bh_process_ace(db, ace, "h2", sid_to_hid, sid_to_cid, seen, edges, stats)
        assert stats["acl_edges"] == 1

    def test_unknown_right(self):
        seen = set()
        edges = []
        stats = {"acl_edges": 0}
        db = MagicMock()
        ace = {"RightName": "unknown", "PrincipalSID": "s1"}
        _bh_process_ace(db, ace, "h2", {}, {}, seen, edges, stats)
        assert stats["acl_edges"] == 0


class TestParseBloodhoundJson:
    def test_invalid_json(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            parse_bloodhound_json("p1", "computers", b"not json", MagicMock())
        assert exc_info.value.status_code == 400

    def test_valid_empty(self):
        from fastapi import HTTPException
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = []
        db.query.return_value.filter.return_value.first.return_value = None
        result = parse_bloodhound_json("p1", "computers", b'{"data": []}', db)
        assert "hosts_created" in result
