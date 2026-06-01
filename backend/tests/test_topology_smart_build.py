import pytest
from unittest.mock import MagicMock, patch

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
    _add_smart_edge,
    _EdgeAcc,
    _sb_p1_resolve_from_nid,
    _sb_p1_cred_label,
    _sb_p4_build_dc_map,
    _sb_host_meta,
    _is_junction_host,
    _sb_infer_entry_cidrs,
    _sb_p13_collect_public_hosts,
    _STATUS_RANK,
    _TOPO_WEB_PORTS,
    _TOPO_DB_PORTS,
    _JUNCTION_ROLES,
    _JUNCTION_TAGS,
    _JUNCTION_PREFIXES,
)
import ipaddress


class TestIsDcNode:
    def test_role(self):
        assert _is_dc_node("domain_controller", set(), []) is True

    def test_dc_role(self):
        assert _is_dc_node("dc", set(), []) is True

    def test_tag(self):
        assert _is_dc_node("", {"dc"}, []) is True

    def test_ports(self):
        assert _is_dc_node("", set(), ["88/tcp", "389/tcp"]) is True

    def test_no(self):
        assert _is_dc_node("server", set(), ["80/tcp"]) is False


class TestIsRouterNode:
    def test_role(self):
        for r in ("router", "firewall", "network_device"):
            assert _is_router_node(r, set()) is True

    def test_tag(self):
        assert _is_router_node("", {"router"}) is True
        assert _is_router_node("", {"firewall"}) is True
        assert _is_router_node("", {"gateway"}) is True

    def test_no(self):
        assert _is_router_node("server", set()) is False


class TestIsJumpNode:
    def test_role(self):
        assert _is_jump_node("jump_host", set()) is True

    def test_tag(self):
        assert _is_jump_node("", {"jump"}) is True

    def test_no(self):
        assert _is_jump_node("server", set()) is False


class TestIsFileServerNode:
    def test_yes(self):
        assert _is_file_server_node(["445/tcp"], "windows server") is True

    def test_no_port(self):
        assert _is_file_server_node(["80/tcp"], "windows server") is False

    def test_no_os(self):
        assert _is_file_server_node(["445/tcp"], "workstation") is False


class TestIsWorkstationNode:
    def test_yes(self):
        assert _is_workstation_node("windows 10") is True

    def test_server(self):
        assert _is_workstation_node("windows server 2019") is False

    def test_linux(self):
        assert _is_workstation_node("linux") is False


class TestInferNodeRole:
    def test_attacker(self):
        assert _infer_node_role({"is_attacker": True}) == "attacker"
        assert _infer_node_role({"role": "attacker"}) == "attacker"

    def test_dc(self):
        assert _infer_node_role({"role": "domain_controller", "tags": [], "ports": []}) == "domain_controller"

    def test_router(self):
        assert _infer_node_role({"role": "router", "tags": [], "ports": []}) == "router"

    def test_jump(self):
        assert _infer_node_role({"role": "", "tags": ["jump"], "ports": []}) == "jump_host"

    def test_file_server(self):
        assert _infer_node_role({"ports": ["445/tcp"], "os": "windows server", "tags": [], "role": ""}) == "file_server"

    def test_web_server(self):
        assert _infer_node_role({"ports": ["80/tcp"], "tags": [], "role": "", "os": ""}) == "web_server"

    def test_database(self):
        assert _infer_node_role({"ports": ["3306/tcp"], "tags": [], "role": "", "os": ""}) == "database"

    def test_workstation(self):
        assert _infer_node_role({"ports": [], "tags": [], "role": "", "os": "windows 10"}) == "workstation"

    def test_default_server(self):
        assert _infer_node_role({"ports": [], "tags": [], "role": "", "os": ""}) == "server"

    def test_existing_role(self):
        assert _infer_node_role({"ports": [], "tags": [], "role": "custom", "os": ""}) == "custom"


class TestHInAnyCidr:
    def test_in(self):
        h = MagicMock()
        h.ip = "10.0.0.1"
        cidrs = [ipaddress.ip_network("10.0.0.0/24")]
        assert _h_in_any_cidr(h, cidrs) is True

    def test_not_in(self):
        h = MagicMock()
        h.ip = "192.168.1.1"
        cidrs = [ipaddress.ip_network("10.0.0.0/24")]
        assert _h_in_any_cidr(h, cidrs) is False

    def test_no_ip(self):
        h = MagicMock()
        h.ip = ""
        assert _h_in_any_cidr(h, []) is False

    def test_invalid_ip(self):
        h = MagicMock()
        h.ip = "invalid"
        assert _h_in_any_cidr(h, []) is False


class TestLookupScopeForIp:
    def test_found(self):
        sr = {"net_obj": ipaddress.ip_network("10.0.0.0/24"), "cidr": "10.0.0.0/24"}
        assert _lookup_scope_for_ip("10.0.0.1", [sr]) is not None

    def test_not_found(self):
        sr = {"net_obj": ipaddress.ip_network("10.0.0.0/24"), "cidr": "10.0.0.0/24"}
        assert _lookup_scope_for_ip("192.168.1.1", [sr]) is None

    def test_empty_ip(self):
        assert _lookup_scope_for_ip("", []) is None


class TestHostIsDc:
    def test_role(self):
        assert _host_is_dc({"role": "domain_controller", "tags": [], "ports": []}) is True

    def test_tag(self):
        assert _host_is_dc({"role": "", "tags": ["dc"], "ports": []}) is True

    def test_ports(self):
        assert _host_is_dc({"role": "", "tags": [], "ports": ["88/tcp", "389/tcp"]}) is True

    def test_no(self):
        assert _host_is_dc({"role": "server", "tags": [], "ports": []}) is False


class TestAddSmartEdge:
    def test_basic(self):
        acc = _EdgeAcc(set(), {"n1": {"id": "n1"}, "n2": {"id": "n2"}}, set())
        with patch("app.routers.topology._smart_build._edge_ref", return_value=""):
            r = _add_smart_edge(acc, "n1", "n2", {"source": "auto"})
            assert r is True
            assert len(acc.new_auto_edges) == 1

    def test_same_id(self):
        acc = _EdgeAcc(set(), {}, set())
        assert _add_smart_edge(acc, "n1", "n1", {}) is False

    def test_empty_id(self):
        acc = _EdgeAcc(set(), {}, set())
        assert _add_smart_edge(acc, "", "n2", {}) is False
        assert _add_smart_edge(acc, "n1", "", {}) is False

    def test_duplicate(self):
        acc = _EdgeAcc(set(), {"n1": {}, "n2": {}}, set())
        with patch("app.routers.topology._smart_build._edge_ref", return_value=""):
            _add_smart_edge(acc, "n1", "n2", {"source": "auto"})
            r = _add_smart_edge(acc, "n1", "n2", {"source": "auto"})
            assert r is False

    def test_suppressed(self):
        acc = _EdgeAcc(set(), {"n1": {"host_id": "h1"}, "n2": {"host_id": "h2"}}, {"h1::h2"})
        r = _add_smart_edge(acc, "n1", "n2", {"source": "auto"})
        assert r is False

    def test_stale_count(self):
        acc = _EdgeAcc(set(), {"n1": {}, "n2": {}}, set())
        with patch("app.routers.topology._smart_build._edge_ref", return_value=""):
            _add_smart_edge(acc, "n1", "n2", {"source": "auto", "state": "stale"})
            assert acc.edges_stale == 1

    def test_by_source(self):
        acc = _EdgeAcc(set(), {"n1": {}, "n2": {}}, set())
        with patch("app.routers.topology._smart_build._edge_ref", return_value=""):
            _add_smart_edge(acc, "n1", "n2", {"source": "cred_validation"})
            assert acc.edges_by_source.get("cred_validation") == 1


class TestSbP1ResolveFromNid:
    def test_attacker_nids(self):
        ctx = MagicMock()
        ctx.attacker_nids = ["atk1"]
        assert _sb_p1_resolve_from_nid(ctx, None, "t1") == "atk1"

    def test_cred_host(self):
        ctx = MagicMock()
        ctx.attacker_nids = []
        ctx.hid_to_nid = {"h1": "n1"}
        cred = MagicMock()
        cred.host_ids = ["h1"]
        assert _sb_p1_resolve_from_nid(ctx, cred, "t2") == "n1"

    def test_no_match(self):
        ctx = MagicMock()
        ctx.attacker_nids = []
        ctx.hid_to_nid = {}
        assert _sb_p1_resolve_from_nid(ctx, None, "t1") is None


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


class TestSbP4BuildDcMap:
    def test_basic(self):
        hosts = [
            {"id": "h1", "role": "domain_controller", "domain": "corp",
             "ip": "10.0.0.1", "tags": [], "ports": []},
            {"id": "h2", "role": "domain_controller", "domain": "corp",
             "ip": "10.0.0.2", "tags": [], "ports": []},
        ]
        r = _sb_p4_build_dc_map(hosts)
        assert "corp" in r
        assert r["corp"]["id"] == "h1"


class TestHostMeta:
    def test_basic(self):
        h = MagicMock()
        h.id = "h1"
        h.ip = "10.0.0.1"
        h.hostname = "srv"
        h.os = "Linux"
        h.status = "up"
        h.role = "server"
        h.is_attacker = False
        h.ips = ["10.0.0.1"]
        h.ports = ["80/tcp"]
        h.services = ["http"]
        h.tags = ["nmap"]
        h.domain = "corp"
        with patch("app.routers.topology._smart_build._annotate_ip_subnet", return_value="10.0.0.0/24"):
            r = _sb_host_meta(h, [])
            assert r["id"] == "h1"
            assert r["ip"] == "10.0.0.1"
            assert r["subnet"] == "10.0.0.0/24"


class TestIsJunctionHost:
    def test_role(self):
        for r in _JUNCTION_ROLES:
            h = MagicMock()
            h.is_attacker = False
            h.role = r
            h.tags = []
            h.hostname = ""
            assert _is_junction_host(h) is True

    def test_tag(self):
        for t in _JUNCTION_TAGS:
            h = MagicMock()
            h.is_attacker = False
            h.role = ""
            h.tags = [t]
            h.hostname = ""
            assert _is_junction_host(h) is True

    def test_prefix(self):
        for p in _JUNCTION_PREFIXES:
            h = MagicMock()
            h.is_attacker = False
            h.role = ""
            h.tags = []
            h.hostname = f"{p}-01"
            assert _is_junction_host(h) is True

    def test_attacker(self):
        h = MagicMock()
        h.is_attacker = True
        assert _is_junction_host(h) is False

    def test_normal(self):
        h = MagicMock()
        h.is_attacker = False
        h.role = "server"
        h.tags = []
        h.hostname = "web01"
        assert _is_junction_host(h) is False


class TestSbInferEntryCidrs:
    def test_basic(self):
        srs = [{"is_entry": True, "cidr": "10.0.0.0/24"}, {"is_entry": False, "cidr": "192.168.0.0/24"}]
        r = _sb_infer_entry_cidrs(srs)
        assert len(r) == 1
        assert r[0] == ipaddress.ip_network("10.0.0.0/24")

    def test_empty(self):
        assert _sb_infer_entry_cidrs([]) == []


class TestSbP13CollectPublicHosts:
    def test_public_ip(self):
        hosts = [{"ip": "8.8.8.8", "is_attacker": False, "tags": []}]
        with patch("app.routers.topology._smart_build._is_rfc1918", return_value=False):
            r = _sb_p13_collect_public_hosts(hosts)
            assert len(r) == 1

    def test_tagged(self):
        from app.routers.topology._edge_meta import _PUBLIC_TAGS
        hosts = [{"ip": "10.0.0.1", "is_attacker": False, "tags": list(_PUBLIC_TAGS)}]
        with patch("app.routers.topology._smart_build._is_rfc1918", return_value=True):
            r = _sb_p13_collect_public_hosts(hosts)
            assert len(r) == 1

    def test_attacker_excluded(self):
        hosts = [{"ip": "8.8.8.8", "is_attacker": True, "tags": []}]
        r = _sb_p13_collect_public_hosts(hosts)
        assert len(r) == 0

    def test_private(self):
        hosts = [{"ip": "10.0.0.1", "is_attacker": False, "tags": []}]
        with patch("app.routers.topology._smart_build._is_rfc1918", return_value=True):
            r = _sb_p13_collect_public_hosts(hosts)
            assert len(r) == 0


class TestStatusRank:
    def test_ordering(self):
        for lower, higher in [("unknown", "up"), ("up", "access"), ("access", "pwned"),
                               ("pwned", "attacker")]:
            assert _STATUS_RANK[lower] < _STATUS_RANK[higher]


class TestPortSets:
    def test_web_ports(self):
        assert "80/tcp" in _TOPO_WEB_PORTS
        assert "443/tcp" in _TOPO_WEB_PORTS

    def test_db_ports(self):
        assert "3306/tcp" in _TOPO_DB_PORTS
        assert "5432/tcp" in _TOPO_DB_PORTS
