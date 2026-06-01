"""Consolidated tests for test_bloodhound (merged variant files)."""

# ════════ from test_bloodhound_final.py ════════
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


class TestHostShort_final:
    def test_fqdn(self):
        assert _host_short("SDOTSON.EDU.STF") == "SDOTSON"

    def test_single(self):
        assert _host_short("SERVER") == "SERVER"

    def test_empty(self):
        assert _host_short("") == ""


class TestUserShort_final:
    def test_email(self):
        assert _user_short("S_DOTSON@EDU.STF") == "s_dotson"

    def test_plain(self):
        assert _user_short("admin") == "admin"

    def test_empty(self):
        assert _user_short("") == ""


class TestGetItems_final:
    def test_data_key(self):
        assert _get_items({"data": [1, 2]}) == [1, 2]

    def test_computers_key(self):
        assert _get_items({"computers": [{"id": "c1"}]}) == [{"id": "c1"}]

    def test_empty(self):
        assert _get_items({}) == []


class TestAddHostTag_final:
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


class TestBhAddEdge_final:
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


class TestBhDcOrTag_final:
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


class TestBhBuildIndex_final:
    def test_basic(self):
        h = MagicMock()
        h.hostname = "SRV1"
        c = MagicMock()
        c.username = "admin"
        c.service = "AD"
        host_idx, cred_idx = _bh_build_index([h], [c])
        assert "SRV1" in host_idx
        assert "admin" in cred_idx


class TestBhTrustTypeDir_final:
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


class TestParseBloodhoundJson_final:
    def test_invalid_json(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            parse_bloodhound_json("p1", "computers", b"not json", MagicMock())


class TestAclEdgeMap:
    def test_contains_expected(self):
        assert "genericall" in _ACL_EDGE_MAP
        assert "dcsyncrights" in _ACL_EDGE_MAP


# ════════ from test_bloodhound_final2.py ════════
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


class TestHostShort_final2:
    def test_fqdn(self):
        assert _host_short("SRV01.CORP.LOCAL") == "SRV01"

    def test_empty(self):
        assert _host_short("") == ""


class TestUserShort_final2:
    def test_upn(self):
        assert _user_short("ADMIN@CORP.LOCAL") == "admin"

    def test_plain(self):
        assert _user_short("admin") == "admin"


class TestGetItems_final2:
    def test_data_key(self):
        assert _get_items({"data": [1, 2]}) == [1, 2]

    def test_computers_key(self):
        assert _get_items({"computers": [1]}) == [1]

    def test_empty(self):
        assert _get_items({}) == []


class TestAddHostTag_final2:
    def test_new_tag(self):
        host = MagicMock()
        host.tags = ["existing"]
        assert _add_host_tag(host, "new") is True
        assert "new" in host.tags

    def test_duplicate_tag(self):
        host = MagicMock()
        host.tags = ["existing"]
        assert _add_host_tag(host, "existing") is False


class TestBhAddEdge_final2:
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


class TestBhDcOrTag_final2:
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


class TestBhBuildIndex_final2:
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


class TestBhTrustTypeDir_final2:
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


class TestParseBloodhoundJson_final2:
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


# ════════ from test_bloodhound_v3.py ════════
import pytest
from unittest.mock import MagicMock, patch

from app.routers.import_bloodhound import (
    _host_short,
    _user_short,
    _get_items,
    _now,
    _edge_id,
    _DA_GROUP_NAMES,
    _HIGH_PRIV_ACES,
)


class TestHostShort_v3:
    def test_fqdn(self):
        assert _host_short("SRV01.CORP.LOCAL") == "SRV01"

    def test_simple(self):
        assert _host_short("SRV01") == "SRV01"

    def test_empty(self):
        assert _host_short("") == ""

    def test_lowercase(self):
        assert _host_short("srv01.corp.local") == "SRV01"


class TestUserShort_v3:
    def test_upn(self):
        assert _user_short("ADMIN@CORP.LOCAL") == "admin"

    def test_simple(self):
        assert _user_short("admin") == "admin"

    def test_empty(self):
        assert _user_short("") == ""


class TestGetItems_v3:
    def test_data_key(self):
        assert _get_items({"data": [1, 2]}) == [1, 2]

    def test_computers_key(self):
        assert _get_items({"computers": [{"name": "SRV"}]}) == [{"name": "SRV"}]

    def test_users_key(self):
        assert _get_items({"users": [{"name": "admin"}]}) == [{"name": "admin"}]

    def test_groups_key(self):
        assert _get_items({"groups": [{"name": "DA"}]}) == [{"name": "DA"}]

    def test_sessions_key(self):
        assert _get_items({"sessions": [1]}) == [1]

    def test_empty(self):
        assert _get_items({}) == []


class TestNow:
    def test_returns_string(self):
        with patch("app.routers.import_bloodhound.ts_now", return_value="ts"):
            assert _now() == "ts"


class TestEdgeId:
    def test_format(self):
        eid = _edge_id()
        assert eid.startswith("bh_")
        assert len(eid) == 13


class TestConstants:
    def test_da_groups(self):
        assert "domain admins" in _DA_GROUP_NAMES
        assert "enterprise admins" in _DA_GROUP_NAMES

    def test_high_priv(self):
        assert "genericall" in _HIGH_PRIV_ACES
