import pytest
from unittest.mock import MagicMock, patch
import ipaddress

from app.routers.topology._smart_build import (
    _is_dc_node,
    _is_router_node,
    _is_jump_node,
    _is_file_server_node,
    _is_workstation_node,
    _infer_node_role,
    _h_in_any_cidr,
    _lookup_scope_for_ip,
    _host_is_dc,
    _EdgeAcc,
    _add_smart_edge,
    _SBCtx,
    _sb_p1_resolve_from_nid,
    _sb_p1_cred_label,
    _STATUS_RANK,
)


class TestIsFileServerNode:
    def test_true(self):
        assert _is_file_server_node(["445/tcp"], "windows server 2019") is True

    def test_no_445(self):
        assert _is_file_server_node(["80/tcp"], "windows server") is False

    def test_no_server(self):
        assert _is_file_server_node(["445/tcp"], "windows 10") is False


class TestIsWorkstationNode:
    def test_true(self):
        assert _is_workstation_node("windows 10 pro") is True

    def test_server(self):
        assert _is_workstation_node("windows server 2019") is False

    def test_linux(self):
        assert _is_workstation_node("linux") is False


class TestInferNodeRole:
    def test_attacker(self):
        assert _infer_node_role({"is_attacker": True}) == "attacker"

    def test_attacker_role(self):
        assert _infer_node_role({"role": "attacker"}) == "attacker"

    def test_dc_by_role(self):
        assert _infer_node_role({"role": "dc", "tags": [], "ports": [], "os": ""}) == "domain_controller"

    def test_dc_by_tags(self):
        assert _infer_node_role({"tags": ["dc"], "ports": [], "os": "", "role": ""}) == "domain_controller"

    def test_router(self):
        assert _infer_node_role({"role": "router", "tags": [], "ports": [], "os": ""}) == "router"

    def test_jump(self):
        assert _infer_node_role({"role": "jump_host", "tags": [], "ports": [], "os": ""}) == "jump_host"

    def test_file_server(self):
        assert _infer_node_role({"ports": ["445/tcp"], "os": "windows server", "tags": [], "role": ""}) == "file_server"

    def test_web_server(self):
        assert _infer_node_role({"ports": ["80/tcp", "443/tcp"], "os": "linux", "tags": [], "role": ""}) == "web_server"

    def test_database(self):
        assert _infer_node_role({"ports": ["5432/tcp"], "os": "linux", "tags": [], "role": ""}) == "database"

    def test_workstation(self):
        assert _infer_node_role({"ports": [], "os": "windows 10", "tags": [], "role": ""}) == "workstation"

    def test_default_server(self):
        assert _infer_node_role({"ports": [], "os": "linux", "tags": [], "role": ""}) == "server"

    def test_preserves_role(self):
        assert _infer_node_role({"ports": [], "os": "linux", "tags": [], "role": "web_proxy"}) == "web_proxy"


class TestHInAnyCidr:
    def test_in_cidr(self):
        h = MagicMock()
        h.ip = "10.0.0.5"
        cidrs = [ipaddress.ip_network("10.0.0.0/24")]
        assert _h_in_any_cidr(h, cidrs) is True

    def test_not_in_cidr(self):
        h = MagicMock()
        h.ip = "192.168.1.1"
        cidrs = [ipaddress.ip_network("10.0.0.0/24")]
        assert _h_in_any_cidr(h, cidrs) is False

    def test_no_ip(self):
        h = MagicMock()
        h.ip = ""
        cidrs = [ipaddress.ip_network("10.0.0.0/24")]
        assert _h_in_any_cidr(h, cidrs) is False

    def test_invalid_ip(self):
        h = MagicMock()
        h.ip = "invalid"
        cidrs = [ipaddress.ip_network("10.0.0.0/24")]
        assert _h_in_any_cidr(h, cidrs) is False


class TestLookupScopeForIp:
    def test_found(self):
        net = ipaddress.ip_network("10.0.0.0/24")
        sr = {"net_obj": net, "name": "scope1"}
        with patch("app.routers.topology._edge_meta._ip_in_network", return_value=True):
            r = _lookup_scope_for_ip("10.0.0.5", [sr])
            assert r["name"] == "scope1"

    def test_not_found(self):
        net = ipaddress.ip_network("10.0.0.0/24")
        sr = {"net_obj": net, "name": "scope1"}
        with patch("app.routers.topology._edge_meta._ip_in_network", return_value=False):
            r = _lookup_scope_for_ip("192.168.1.1", [sr])
            assert r is None

    def test_empty_ip(self):
        r = _lookup_scope_for_ip("", [MagicMock()])
        assert r is None


class TestHostIsDc:
    def test_by_role(self):
        assert _host_is_dc({"role": "dc"}) is True

    def test_by_domain_controller(self):
        assert _host_is_dc({"role": "domain_controller"}) is True

    def test_by_tags(self):
        assert _host_is_dc({"tags": ["dc"], "role": "", "ports": []}) is True

    def test_by_ports(self):
        assert _host_is_dc({"ports": ["88/tcp", "389/tcp"], "role": "", "tags": []}) is True

    def test_no(self):
        assert _host_is_dc({"role": "", "tags": [], "ports": []}) is False


class TestEdgeAcc:
    def test_init(self):
        acc = _EdgeAcc(set(), {}, set())
        assert acc.new_auto_edges == []
        assert acc.edges_stale == 0

    def test_add_smart_edge(self):
        node_by_id = {"n1": {"id": "n1"}, "n2": {"id": "n2"}}
        acc = _EdgeAcc(set(), node_by_id, set())
        r = _add_smart_edge(acc, "n1", "n2", {"source": "test", "type": "ssh"})
        assert r is True
        assert len(acc.new_auto_edges) == 1

    def test_add_smart_edge_dedup(self):
        node_by_id = {"n1": {"id": "n1"}, "n2": {"id": "n2"}}
        acc = _EdgeAcc(set(), node_by_id, set())
        _add_smart_edge(acc, "n1", "n2", {"source": "test"})
        r = _add_smart_edge(acc, "n1", "n2", {"source": "test"})
        assert r is False

    def test_add_smart_edge_reverse_dedup(self):
        node_by_id = {"n1": {"id": "n1"}, "n2": {"id": "n2"}}
        acc = _EdgeAcc(set(), node_by_id, set())
        _add_smart_edge(acc, "n1", "n2", {"source": "test"})
        r = _add_smart_edge(acc, "n2", "n1", {"source": "test"})
        assert r is False

    def test_add_smart_edge_self(self):
        acc = _EdgeAcc(set(), {}, set())
        r = _add_smart_edge(acc, "n1", "n1", {"source": "test"})
        assert r is False

    def test_add_smart_edge_empty(self):
        acc = _EdgeAcc(set(), {}, set())
        r = _add_smart_edge(acc, "", "n2", {"source": "test"})
        assert r is False

    def test_add_smart_edge_stale(self):
        node_by_id = {"n1": {"id": "n1"}, "n2": {"id": "n2"}}
        acc = _EdgeAcc(set(), node_by_id, set())
        _add_smart_edge(acc, "n1", "n2", {"source": "test", "state": "stale"})
        assert acc.edges_stale == 1


class TestSBCtx:
    def test_init(self):
        ctx = _SBCtx()
        assert ctx.pid == ""
        assert ctx.edges_added == 0
        assert ctx.tier_counts == {"tier_0": 0, "tier_1": 0, "tier_2": 0}


class TestSbP1ResolveFromNid:
    def test_attacker_nids(self):
        ctx = _SBCtx()
        ctx.attacker_nids = ["a1"]
        r = _sb_p1_resolve_from_nid(ctx, None, "t1")
        assert r == "a1"

    def test_from_cred_host_ids(self):
        ctx = _SBCtx()
        ctx.attacker_nids = []
        ctx.hid_to_nid = {"h1": "n1"}
        cred = MagicMock()
        cred.host_ids = ["h1"]
        r = _sb_p1_resolve_from_nid(ctx, cred, "t1")
        assert r == "n1"

    def test_no_resolve(self):
        ctx = _SBCtx()
        ctx.attacker_nids = []
        r = _sb_p1_resolve_from_nid(ctx, None, "t1")
        assert r is None


class TestSbP1CredLabel:
    def test_with_domain(self):
        cred = MagicMock()
        cred.domain = "corp"
        cred.username = "admin"
        assert _sb_p1_cred_label(cred) == "corp\\admin"

    def test_no_domain(self):
        cred = MagicMock()
        cred.domain = ""
        cred.username = "admin"
        assert _sb_p1_cred_label(cred) == "admin"

    def test_none(self):
        assert _sb_p1_cred_label(None) == ""
