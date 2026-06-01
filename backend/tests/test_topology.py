"""Consolidated tests for test_topology (merged variant files)."""

# ════════ from test_topology_api.py ════════
import io
import math
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app import models
from app.core.utils import new_id
from app.plugins.loader import _register_builtin_modules
from app.plugins.registry import registry

_register_builtin_modules()

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
TS = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    r = module_client.post("/api/projects", json={"name": "TopologyTest", "added": TS, "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]

    r = module_client.post("/api/hosts", json={
        "pid": _state["pid"], "ip": "10.0.0.1", "hostname": "topo-dc01",
        "os": "Windows Server 2022", "status": "alive", "ports": ["88/tcp", "389/tcp", "445/tcp"],
        "services": [], "tags": [], "notes": "", "domain": "corp.local",
        "role": "domain_controller",
    })
    assert r.status_code == 201
    _state["hid_dc"] = r.json()["id"]

    r = module_client.post("/api/hosts", json={
        "pid": _state["pid"], "ip": "10.0.0.2", "hostname": "topo-ws01",
        "os": "Windows 10", "status": "alive", "ports": ["445/tcp"],
        "services": [], "tags": [], "notes": "", "domain": "corp.local",
    })
    assert r.status_code == 201
    _state["hid_ws"] = r.json()["id"]

    r = module_client.post("/api/hosts", json={
        "pid": _state["pid"], "ip": "10.0.0.100", "hostname": "topo-attacker",
        "os": "Linux", "status": "attacker", "ports": [],
        "services": [], "tags": ["attacker"], "notes": "",
        "role": "attacker", "is_attacker": True,
    })
    assert r.status_code == 201
    _state["hid_att"] = r.json()["id"]

    yield
    module_client.post("/api/auth/logout")


NMAP_XML_SINGLE = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
<host>
  <status state="up"/>
  <address addrtype="ipv4" addr="10.0.0.5"/>
  <hostnames><hostname type="PTR" name="topo-new.corp.local"/></hostnames>
  <os><osmatch name="Linux 5.4"/></os>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open"/>
      <service name="ssh" product="OpenSSH 8.9"/>
    </port>
    <port protocol="tcp" portid="80">
      <state state="open"/>
      <service name="http" product="nginx"/>
    </port>
  </ports>
</host>
</nmaprun>"""

NMAP_XML_MULTI = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
<host>
  <status state="up"/>
  <address addrtype="ipv4" addr="10.0.1.1"/>
  <hostnames><hostname type="PTR" name="srv01.corp.local"/></hostnames>
  <os><osmatch name="Windows Server 2019"/></os>
  <ports>
    <port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port>
  </ports>
</host>
<host>
  <status state="up"/>
  <address addrtype="ipv4" addr="10.0.1.2"/>
  <hostnames><hostname type="PTR" name="srv02.corp.local"/></hostnames>
  <os><osmatch name="Windows Server 2019"/></os>
  <ports>
    <port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port>
    <port protocol="tcp" portid="1433"><state state="open"/><service name="mssql"/></port>
  </ports>
</host>
</nmaprun>"""

NMAP_XML_INVALID = "<not-nmap>nope</not-nmap>"


class TestTopologySources:
    def test_get_sources(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/topology/sources")
        assert r.status_code == 200
        data = r.json()
        assert "sources" in data
        ids = [s["id"] for s in data["sources"]]
        assert "nmap" in ids


class TestTopologyGet:
    def test_get_topology_empty(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/topology")
        assert r.status_code == 200
        data = r.json()
        assert data["project_id"] == _state["pid"]
        assert data["host_count"] >= 3

    def test_get_topology_404(self, module_client: TestClient):
        r = module_client.get("/api/projects/nonexistent/topology")
        assert r.status_code == 404


class TestTopologyPreview:
    def test_preview_nmap_xml(self, module_client: TestClient):
        r = module_client.post(
            f"/api/projects/{_state['pid']}/topology/preview",
            files={"file": ("scan.xml", NMAP_XML_SINGLE.encode(), "text/xml")},
            data={"source_type": "nmap"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["host_count"] >= 1
        assert data["scan_source"] == "nmap"

    def test_preview_multi_host(self, module_client: TestClient):
        r = module_client.post(
            f"/api/projects/{_state['pid']}/topology/preview",
            files={"file": ("scan.xml", NMAP_XML_MULTI.encode(), "text/xml")},
            data={"source_type": "nmap", "create_links": "true"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["host_count"] >= 2

    def test_preview_no_file(self, module_client: TestClient):
        r = module_client.post(
            f"/api/projects/{_state['pid']}/topology/preview",
            data={"source_type": "nmap"},
        )
        assert r.status_code == 400

    def test_preview_invalid_source_type(self, module_client: TestClient):
        r = module_client.post(
            f"/api/projects/{_state['pid']}/topology/preview",
            files={"file": ("scan.xml", b"<xml/>", "text/xml")},
            data={"source_type": "burp"},
        )
        assert r.status_code == 400

    def test_preview_404_project(self, module_client: TestClient):
        r = module_client.post(
            "/api/projects/nonexistent/topology/preview",
            files={"file": ("scan.xml", NMAP_XML_SINGLE.encode(), "text/xml")},
            data={"source_type": "nmap"},
        )
        assert r.status_code == 404


class TestTopologyApply:
    def test_apply_from_preview(self, module_client: TestClient):
        r = module_client.post(
            f"/api/projects/{_state['pid']}/topology/preview",
            files={"file": ("scan.xml", NMAP_XML_SINGLE.encode(), "text/xml")},
            data={"source_type": "nmap", "create_links": "true"},
        )
        assert r.status_code == 200
        preview = r.json()

        r = module_client.post(
            f"/api/projects/{_state['pid']}/topology/apply",
            json={"preview": preview, "options": {"create_missing_networks": True}},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert "job_id" in data

    def test_apply_404_project(self, module_client: TestClient):
        r = module_client.post(
            "/api/projects/nonexistent/topology/apply",
            json={"preview": {"new_hosts": [], "updated_hosts": [], "new_links": []}},
        )
        assert r.status_code == 404


class TestTopologyAutoBuild:
    def test_auto_build(self, module_client: TestClient):
        r = module_client.post(
            f"/api/projects/{_state['pid']}/topology/auto-build",
            json={"keep_manual_positions": True, "create_missing_networks": True},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert "job_id" in data

    def test_auto_build_404(self, module_client: TestClient):
        r = module_client.post(
            "/api/projects/nonexistent/topology/auto-build",
            json={},
        )
        assert r.status_code == 500


class TestTopologySmartBuild:
    def test_smart_build(self, module_client: TestClient):
        r = module_client.post(
            f"/api/projects/{_state['pid']}/topology/smart-build",
            json={"keep_manual_positions": True, "create_missing_networks": True},
        )
        # Must succeed — previously this also accepted 500, which masked a
        # NameError in _run_smart_build (ctx.dry_run / ctx.keep_manual_positions
        # referenced without the ctx. prefix). Keep it strict so that regression
        # can't slip back in unnoticed.
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["ok"] is True
        assert "job_id" in data

    def test_smart_build_dry_run(self, module_client: TestClient):
        """dry_run path exercises ctx.dry_run + rollback — the other half of the
        NameError fix. Must return ok without persisting."""
        r = module_client.post(
            f"/api/projects/{_state['pid']}/topology/smart-build",
            json={"keep_manual_positions": True, "preserve_positions": True, "dry_run": True},
        )
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["ok"] is True

    def test_smart_build_404(self, module_client: TestClient):
        r = module_client.post(
            "/api/projects/nonexistent/topology/smart-build",
            json={},
        )
        assert r.status_code == 500


class TestTopologyRebuildLayout:
    def test_rebuild_layout(self, module_client: TestClient):
        module_client.post(
            f"/api/projects/{_state['pid']}/topology/auto-build",
            json={"create_missing_networks": True},
        )
        r = module_client.post(
            f"/api/projects/{_state['pid']}/topology/rebuild-layout",
            json={"keep_manual_positions": True},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True

    def test_rebuild_layout_404_project(self, module_client: TestClient):
        r = module_client.post(
            "/api/projects/nonexistent/topology/rebuild-layout",
            json={},
        )
        assert r.status_code == 404

    def test_rebuild_layout_no_network(self, module_client: TestClient):
        r = module_client.post("/api/projects", json={"name": "NoNetworkTopo", "added": TS, "status": "active"})
        pid = r.json()["id"]
        r = module_client.post(
            f"/api/projects/{pid}/topology/rebuild-layout",
            json={},
        )
        assert r.status_code == 404


class TestTopologyLateralPaths:
    def test_lateral_paths(self, module_client: TestClient):
        r = module_client.get(
            f"/api/projects/{_state['pid']}/topology/lateral-paths",
            params={"from_host_id": _state["hid_att"], "depth": 3},
        )
        assert r.status_code == 200
        data = r.json()
        assert "paths" in data

    def test_lateral_paths_no_network(self, module_client: TestClient):
        r = module_client.post("/api/projects", json={"name": "NoNetLateral", "added": TS, "status": "active"})
        pid = r.json()["id"]
        r = module_client.get(
            f"/api/projects/{pid}/topology/lateral-paths",
            params={"from_host_id": "fake", "depth": 2},
        )
        assert r.status_code == 200
        assert r.json()["paths"] == []


class TestParseNmapXml:
    def test_parse_valid_xml(self):
        from app.routers.topology.routes import parse_nmap_xml
        hosts = parse_nmap_xml(NMAP_XML_SINGLE)
        assert len(hosts) == 1
        assert hosts[0]["ip"] == "10.0.0.5"
        assert hosts[0]["hostname"] == "topo-new.corp.local"
        assert "22/tcp" in hosts[0]["ports"]
        assert "80/tcp" in hosts[0]["ports"]

    def test_parse_multi_host(self):
        from app.routers.topology.routes import parse_nmap_xml
        hosts = parse_nmap_xml(NMAP_XML_MULTI)
        assert len(hosts) == 2
        ips = {h["ip"] for h in hosts}
        assert "10.0.1.1" in ips
        assert "10.0.1.2" in ips

    def test_parse_invalid_xml(self):
        from app.routers.topology.routes import parse_nmap_xml
        hosts = parse_nmap_xml(NMAP_XML_INVALID)
        assert hosts == []

    def test_parse_empty_xml(self):
        from app.routers.topology.routes import parse_nmap_xml
        hosts = parse_nmap_xml("<nmaprun/>")
        assert hosts == []


class TestInferLinks:
    def test_infer_links_same_subnet(self):
        from app.routers.topology._infer import infer_links
        hosts = [
            {"ip": "10.0.0.1", "hostname": "a"},
            {"ip": "10.0.0.2", "hostname": "b"},
            {"ip": "10.0.0.3", "hostname": "c"},
        ]
        links = infer_links(hosts)
        assert len(links) >= 1
        for link in links:
            assert link.link_type == "same_subnet"
            assert link.confidence > 0

    def test_infer_links_different_subnets(self):
        from app.routers.topology._infer import infer_links
        hosts = [
            {"ip": "10.0.0.1"},
            {"ip": "192.168.1.1"},
        ]
        links = infer_links(hosts)
        assert len(links) == 0

    def test_infer_links_empty(self):
        from app.routers.topology._infer import infer_links
        assert infer_links([]) == []

    def test_infer_links_single(self):
        from app.routers.topology._infer import infer_links
        assert infer_links([{"ip": "10.0.0.1"}]) == []

    def test_infer_links_smart_basic(self):
        from app.routers.topology._infer import infer_links_smart
        hosts = [
            {"ip": "10.0.0.1", "hostname": "gw", "id": "h1", "ports": ["22/tcp"], "tags": []},
            {"ip": "10.0.0.2", "hostname": "srv", "id": "h2", "ports": ["80/tcp"], "tags": []},
        ]
        links = infer_links_smart(hosts)
        assert len(links) >= 1

    def test_infer_links_smart_empty(self):
        from app.routers.topology._infer import infer_links_smart
        assert infer_links_smart([]) == []

    def test_get_subnet(self):
        from app.routers.topology._infer import _get_subnet
        assert _get_subnet("10.0.0.1") == "10.0.0.0/24"
        assert _get_subnet("192.168.1.50") == "192.168.1.0/24"

    def test_is_gateway(self):
        from app.routers.topology._infer import _is_gateway
        assert _is_gateway({"role": "router"}) is True
        assert _is_gateway({"tags": ["firewall"]}) is True
        assert _is_gateway({"os": "Cisco IOS"}) is True
        assert _is_gateway({"role": "server", "tags": [], "os": "Linux"}) is False

    def test_scope_region_colors(self):
        from app.routers.topology._infer import _scope_region_colors
        s, f = _scope_region_colors("10.0.0.0/24", True)
        assert s.startswith("#")
        assert f.startswith("#")

    def test_midpoint_in_overlap(self):
        from app.routers.topology._infer import _midpoint_in_overlap
        assert _midpoint_in_overlap(0, 10, 5, 10) == 7.5
        assert _midpoint_in_overlap(0, 10, 20, 10) == 15.0

    def test_place_on_region_edge(self):
        from app.routers.topology._infer import _place_on_region_edge
        region = {"x": 100, "y": 100, "w": 200, "h": 150}
        x, y = _place_on_region_edge(region, "left")
        assert x < 100
        x2, y2 = _place_on_region_edge(region, "right")
        assert x2 > 300


class TestEdgeMeta:
    def test_is_rfc1918(self):
        from app.routers.topology._edge_meta import _is_rfc1918
        assert _is_rfc1918("10.0.0.1") is True
        assert _is_rfc1918("172.16.0.1") is True
        assert _is_rfc1918("192.168.1.1") is True
        assert _is_rfc1918("8.8.8.8") is False
        assert _is_rfc1918("127.0.0.1") is True

    def test_is_key_host(self):
        from app.routers.topology._edge_meta import _is_key_host
        assert _is_key_host({"is_attacker": True}) is True
        assert _is_key_host({"role": "domain_controller"}) is True
        assert _is_key_host({"tags": ["firewall"]}) is True
        assert _is_key_host({"role": "workstation", "tags": []}) is False

    def test_role_from_tags(self):
        from app.routers.topology._edge_meta import _role_from_tags
        assert _role_from_tags({"dc"}) == "domain_controller"
        assert _role_from_tags({"router"}) == "router"
        assert _role_from_tags({"database"}) == "database"
        assert _role_from_tags({"unknown"}) is None

    def test_role_from_hostname_patterns(self):
        from app.routers.topology._edge_meta import _role_from_hostname_patterns
        assert _role_from_hostname_patterns("DC01") == "domain_controller"
        assert _role_from_hostname_patterns("EXCHANGE01") == "mail"
        assert _role_from_hostname_patterns("MSSQL01") == "database"
        assert _role_from_hostname_patterns("WEB01") == "web"
        assert _role_from_hostname_patterns("VPN01") == "router"
        assert _role_from_hostname_patterns("RANDOM") is None

    def test_role_from_ports(self):
        from app.routers.topology._edge_meta import _role_from_ports
        assert _role_from_ports({"88/tcp", "389/tcp"}, "", "") == "domain_controller"
        assert _role_from_ports({"1433/tcp"}, "", "") == "database"
        assert _role_from_ports({"25/tcp"}, "", "") == "mail"
        assert _role_from_ports({"80/tcp", "443/tcp"}, "", "") == "web"
        assert _role_from_ports({"445/tcp"}, "corp.local", "") == "workstation"

    def test_edge_action_tags(self):
        from app.routers.topology._edge_meta import _edge_action_tags
        tags = _edge_action_tags("cred_validation")
        assert "mitre_techniques" in tags
        assert "T1078" in tags["mitre_techniques"]

        tags = _edge_action_tags("host_activity", "c2")
        assert tags["kill_chain_stage"] == "command_and_control"

        tags = _edge_action_tags("unknown_source")
        assert tags == {}

    def test_decay_confidence(self):
        from app.routers.topology._edge_meta import _decay_confidence
        c, stale = _decay_confidence(1.0, "", 14.0)
        assert c == 1.0
        assert stale is False

        ts = datetime.now(timezone.utc).isoformat()
        c, stale = _decay_confidence(1.0, ts, 14.0)
        assert c > 0.9
        assert stale is False

        old_ts = "2020-01-01T00:00:00+00:00"
        c, stale = _decay_confidence(1.0, old_ts, 1.0)
        assert c < 0.4
        assert stale is True

    def test_ip_in_network(self):
        from app.routers.topology._edge_meta import _ip_in_network
        import ipaddress
        net = ipaddress.ip_network("10.0.0.0/24")
        assert _ip_in_network("10.0.0.1", net) is True
        assert _ip_in_network("10.0.1.1", net) is False

    def test_score_pivot_candidate(self):
        from app.routers.topology._edge_meta import _score_pivot_candidate
        import ipaddress
        entry_net = ipaddress.ip_network("10.0.0.0/24")
        remote_net = ipaddress.ip_network("10.0.1.0/24")
        h = {"ip": "10.0.0.5", "role": "router", "tags": [], "hostname": "gw"}
        score = _score_pivot_candidate(h, [entry_net], remote_net, set())
        assert score is not None
        assert score > 0

        h2 = {"ip": "10.0.0.50", "role": "workstation", "tags": [], "hostname": "ws"}
        score2 = _score_pivot_candidate(h2, [entry_net], remote_net, set())
        assert score2 is None


class TestLateralPathFinding:
    def test_find_lateral_start_node(self):
        from app.routers.topology._lateral import _find_lateral_start_node
        nodes = [
            {"id": "n1", "host_id": "h1"},
            {"id": "n2", "host_id": "h2"},
        ]
        assert _find_lateral_start_node(nodes, "h1") == "n1"
        assert _find_lateral_start_node(nodes, "n2") == "n2"
        assert _find_lateral_start_node(nodes, "h99") is None

    def test_build_access_adjacency(self):
        from app.routers.topology._lateral import _build_access_adjacency
        edges = [
            {"type": "ssh", "from": "n1", "to": "n2"},
            {"type": "same_subnet", "from": "n2", "to": "n3"},
        ]
        adj = _build_access_adjacency(edges)
        assert "n1" in adj
        assert any(h["to"] == "n2" for h in adj["n1"])

    def test_bfs_lateral_paths(self):
        from app.routers.topology._lateral import _bfs_lateral_paths
        adj = {"n1": [{"to": "n2", "edge": {"type": "ssh", "confidence": 0.9}}]}
        node_map = {"n1": {"label": "A"}, "n2": {"label": "B", "host_id": "h2"}}
        paths = _bfs_lateral_paths(adj, "n1", node_map, 3)
        assert len(paths) == 1
        assert paths[0]["target_node_id"] == "n2"
        assert paths[0]["distance"] == 1


class TestNodeRefHelpers:
    def test_node_ref(self):
        from app.routers.topology.routes import _node_ref
        assert _node_ref({"host_id": "h1", "ip": "10.0.0.1"}) == "h1"
        assert _node_ref({"ip": "10.0.0.1"}) == "10.0.0.1"
        assert _node_ref({}) == ""
        assert _node_ref(None) == ""

    def test_edge_ref(self):
        from app.routers.topology.routes import _edge_ref
        a = {"host_id": "h1"}
        b = {"host_id": "h2"}
        ref = _edge_ref(a, b)
        assert ref != ""
        assert _edge_ref(None, b) == ""
        assert _edge_ref(a, None) == ""


# ════════ from test_topology_v3.py ════════
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
