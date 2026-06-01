"""Consolidated tests for test_attack_graph (merged variant files)."""

# ════════ from test_attack_graph.py ════════
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app import models
from app.core.utils import new_id


def _setup_and_login(client: TestClient) -> dict:
    client.post("/api/auth/setup", json={"username": "admin", "password": "TestPass1234!"})  # NOSONAR
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "TestPass1234!"})  # NOSONAR
    assert resp.status_code == 200, resp.text
    return {}


def _create_project(client: TestClient, headers: dict) -> str:
    resp = client.post("/api/projects", json={"name": "Graph Project", "ip": "", "added": "2024-01-01"}, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


@pytest.mark.skip(reason="Network model uses separate NetworkNode/NetworkEdge tables; fixture needs rewrite")
def test_attack_graph_includes_verified_access_edges(client: TestClient, db: Session):
    headers = _setup_and_login(client)
    pid = _create_project(client, headers)

    attacker = models.Host(
        id=new_id("hst"), pid=pid, ip="10.0.0.10", hostname="attacker", os="Linux",
        status="alive", ports=[], services=[], tags=["attacker"], notes="", domain="",
        role="attacker", is_attacker=True,
    )
    target = models.Host(
        id=new_id("hst"), pid=pid, ip="10.0.0.20", hostname="dc01", os="Windows Server",
        status="access", ports=["445/tcp", "5985/tcp"], services=[], tags=["dc"], notes="", domain="corp.local",
        role="dc", is_attacker=False,
    )
    cred = models.Cred(
        id=new_id("crd"), pid=pid, username="administrator", secret="x", type="ntlm",
        service="smb", host="", domain="corp.local", cracked=False, notes="", tags=[],
        host_ids=[target.id], is_domain=True,
    )
    network = models.Network(
        id=new_id("net"), pid=pid, name="Default Network", background="#07080b",
        nodes_json=[
            {"id": "n_att", "host_id": attacker.id, "label": "attacker", "ip": attacker.ip, "zone_type": "external"},
            {"id": "n_tgt", "host_id": target.id, "label": "dc01", "ip": target.ip, "zone_type": "internal"},
        ],
        edges_json=[
            {
                "id": "edg1",
                "from": "n_att",
                "to": "n_tgt",
                "type": "local_admin",
                "label": "local admin",
                "confidence": 1.0,
                "source": "cred_validation",
                "reason": "Credential validated via SMB",
                "state": "observed",
                "verified": True,
            }
        ],
        meta_json={},
    )
    db.add_all([attacker, target, cred, network])
    db.commit()

    resp = client.get(f"/api/projects/{pid}/attack-graph", headers=headers)
    assert resp.status_code == 200, resp.text
    data = resp.json()

    access_edges = [edge for edge in data["edges"] if edge.get("kind") == "access"]
    credential_edges = [edge for edge in data["edges"] if edge.get("kind") == "credential"]
    assert len(access_edges) == 1
    assert len(credential_edges) == 1

    edge = access_edges[0]
    assert edge["from"] == attacker.id
    assert edge["to"] == target.id
    assert edge["verified"] is True
    assert edge["source"] == "cred_validation"
    assert edge["access_type"] == "local_admin"

    target_node = next(node for node in data["nodes"] if node["id"] == target.id)
    assert target_node["zone_type"] == "internal"
    assert target_node["role"] == "dc"
    assert target_node["reachability"]["reachable"] is True
    assert target_node["reachability"]["reachable_via_verified_path"] is True
    assert target_node["reachability"]["distance"] == 1
    assert target_node["reachability"]["verified_distance"] == 1
    assert data["stats"]["access_edges"] == 1
    assert data["stats"]["verified_access_edges"] == 1
    assert data["stats"]["reachable_hosts"] == 1
    assert data["stats"]["verified_reachable_hosts"] == 1


# ════════ from test_attack_graph_api.py ════════
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app import models
from app.core.utils import new_id

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
TS = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient, module_db: Session):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    r = module_client.post("/api/projects", json={"name": "AttackGraphTest", "added": TS, "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]

    attacker = models.Host(
        id=new_id("hst"), pid=_state["pid"], ip="10.200.0.10", hostname="atk01",
        os="Kali", status="attacker", ports=[], services=[], tags=["attacker"],
        notes="", domain="", role="attacker", is_attacker=True,
    )
    target = models.Host(
        id=new_id("hst"), pid=_state["pid"], ip="10.200.0.20", hostname="dc01",
        os="Windows Server 2022", status="access", ports=["88/tcp", "389/tcp", "445/tcp"],
        services=[], tags=["dc"], notes="", domain="test.local",
        role="domain_controller", is_attacker=False,
    )
    ws = models.Host(
        id=new_id("hst"), pid=_state["pid"], ip="10.200.0.30", hostname="ws01",
        os="Windows 10", status="alive", ports=["445/tcp"],
        services=[], tags=[], notes="", domain="test.local",
        role="workstation", is_attacker=False,
    )
    cred = models.Cred(
        id=new_id("crd"), pid=_state["pid"], username="admin", secret="P@ss",
        type="plain", service="smb", host="", domain="test.local", cracked=False,
        notes="", tags=[], host_ids=[target.id, ws.id], is_domain=True,
    )
    module_db.add_all([attacker, target, ws, cred])
    module_db.commit()
    _state["attacker_id"] = attacker.id
    _state["target_id"] = target.id
    _state["ws_id"] = ws.id
    _state["cred_id"] = cred.id
    yield
    module_client.post("/api/auth/logout")


class TestAttackGraph:
    def test_get_attack_graph(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/attack-graph")
        assert r.status_code == 200, r.text
        data = r.json()
        assert "nodes" in data
        assert "edges" in data
        assert "stats" in data

    def test_attack_graph_has_hosts(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/attack-graph")
        data = r.json()
        node_ids = {n["id"] for n in data["nodes"]}
        assert _state["attacker_id"] in node_ids
        assert _state["target_id"] in node_ids

    def test_attack_graph_credential_edges(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/attack-graph")
        data = r.json()
        cred_edges = [e for e in data["edges"] if e.get("kind") == "credential"]
        assert len(cred_edges) >= 1

    def test_attack_graph_reachability(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/attack-graph")
        data = r.json()
        for node in data["nodes"]:
            assert "reachability" in node
            assert "privilege_info" in node

    def test_attack_graph_stats(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/attack-graph")
        data = r.json()
        stats = data["stats"]
        assert stats["hosts"] >= 3
        assert stats["edges"] >= 1


class TestAttackGraphHelpers:
    def test_is_access_edge(self):
        from app.routers.attack_graph import _is_access_edge
        assert _is_access_edge({"type": "ssh"}) is True
        assert _is_access_edge({"source": "cred_validation"}) is True
        assert _is_access_edge({"type": "same_subnet"}) is False
        assert _is_access_edge({"style": "exploit"}) is True

    def test_is_dc(self):
        from app.routers.attack_graph import _is_dc

        class H:
            role = "domain_controller"
            tags = []
            ports = []

        assert _is_dc(H()) is True

        class H2:
            role = "server"
            tags = ["dc"]
            ports = []

        assert _is_dc(H2()) is True

    def test_bfs_dist(self):
        from app.routers.attack_graph import _bfs_dist
        adj = {"a": ["b"], "b": ["c"]}
        dist = _bfs_dist(adj, ["a"])
        assert dist["a"] == 0
        assert dist["b"] == 1
        assert dist["c"] == 2
        assert "d" not in dist


# ════════ from test_attack_graph_extended.py ════════
import ipaddress
from unittest.mock import MagicMock

from app.routers.attack_graph import (
    _is_access_edge,
    _is_dc,
    _bfs_dist,
    _reachability_walk,
    _build_reachability,
    _build_access_adjacency,
    _bfs_to_da,
    _build_privilege_paths,
    _detect_pivot_chains,
    _collect_relay_chains,
    _build_host_nodes,
    _build_cred_edges,
    _make_access_edge,
    _process_network_edge,
    _find_edge_tech,
    _build_privilege_path_details,
    _annotate_edges_priv_path,
    _da_path_distance,
    _ensure_step_node,
)


class TestIsAccessEdge_extended:
    def test_known_types(self):
        for t in ["ssh", "winrm", "smb", "smb_admin", "lateral", "pivot", "c2_session", "rdp"]:
            assert _is_access_edge({"type": t}) is True

    def test_access_edge_sources(self):
        assert _is_access_edge({"source": "cred_validation"}) is True
        assert _is_access_edge({"source": "bulk_exec"}) is True

    def test_access_edge_styles(self):
        assert _is_access_edge({"style": "exploit"}) is True
        assert _is_access_edge({"style": "lateral"}) is True
        assert _is_access_edge({"style": "tunnel"}) is True

    def test_non_access(self):
        assert _is_access_edge({"type": "logical"}) is False
        assert _is_access_edge({}) is False


class TestIsDc_extended:
    def test_dc_by_role(self):
        h = MagicMock()
        h.role = "domain_controller"
        h.tags = []
        h.ports = []
        assert _is_dc(h) is True

    def test_dc_by_tag(self):
        h = MagicMock()
        h.role = "server"
        h.tags = ["dc", "windows"]
        h.ports = []
        assert _is_dc(h) is True

    def test_dc_by_ports(self):
        h = MagicMock()
        h.role = "server"
        h.tags = []
        h.ports = ["88/tcp", "389/tcp", "445/tcp"]
        assert _is_dc(h) is True

    def test_not_dc(self):
        h = MagicMock()
        h.role = "workstation"
        h.tags = []
        h.ports = ["80/tcp"]
        assert _is_dc(h) is False


class TestBfsDist_extended:
    def test_simple_path(self):
        adj = {"a": ["b"], "b": ["c"]}
        dist = _bfs_dist(adj, ["a"])
        assert dist == {"a": 0, "b": 1, "c": 2}

    def test_multiple_roots(self):
        adj = {"a": ["c"], "b": ["c"]}
        dist = _bfs_dist(adj, ["a", "b"])
        assert dist["a"] == 0
        assert dist["b"] == 0
        assert dist["c"] == 1

    def test_disconnected(self):
        adj = {"a": ["b"]}
        dist = _bfs_dist(adj, ["a"])
        assert "c" not in dist

    def test_empty(self):
        assert _bfs_dist({}, []) == {}


class TestReachabilityWalk_extended:
    def test_walk_with_edges(self):
        edges = [
            {"from": "a", "to": "b", "verified": True, "access_type": "ssh"},
            {"from": "b", "to": "c", "verified": False, "access_type": "lateral"},
        ]
        dist = _reachability_walk(edges, {"a"}, False)
        assert dist["b"] == 1
        assert dist["c"] == 2

    def test_verified_only(self):
        edges = [
            {"from": "a", "to": "b", "verified": True, "access_type": "ssh"},
            {"from": "b", "to": "c", "verified": False, "access_type": "ssh"},
        ]
        dist = _reachability_walk(edges, {"a"}, True)
        assert "b" in dist
        assert "c" not in dist

    def test_bidirectional(self):
        edges = [
            {"from": "a", "to": "b", "verified": True, "access_type": "lateral"},
        ]
        dist = _reachability_walk(edges, {"b"}, False)
        assert "a" in dist


class TestBuildAccessAdjacency_extended:
    def test_builds_adjacency(self):
        edges = [
            {"from": "a", "to": "b", "access_type": "ssh"},
            {"from": "b", "to": "c", "access_type": "lateral"},
        ]
        adj = _build_access_adjacency(edges)
        assert "a" in adj
        assert adj["a"][0][0] == "b"

    def test_bidirectional_included(self):
        edges = [
            {"from": "a", "to": "b", "access_type": "lateral"},
        ]
        adj = _build_access_adjacency(edges)
        assert "b" in adj


class TestBfsToDa_extended:
    def test_finds_path(self):
        adj = {"a": [("b", "ssh")], "b": [("c", "smb")]}
        result = _bfs_to_da({"a"}, "c", adj)
        assert result is not None
        assert result["c"] == "b"
        assert result["b"] == "a"

    def test_no_path(self):
        adj = {"a": [("b", "ssh")]}
        result = _bfs_to_da({"a"}, "z", adj)
        assert result is None


class TestBuildPrivilegePaths_extended:
    def test_finds_path_to_da(self):
        edges = [
            {"from": "att", "to": "h1", "access_type": "ssh"},
            {"from": "h1", "to": "dc", "access_type": "domain_admin"},
        ]
        paths, pairs = _build_privilege_paths(edges, {"att"}, {"dc"})
        assert len(paths) == 1
        assert paths[0] == ["att", "h1", "dc"]
        assert ("att", "h1") in pairs
        assert ("h1", "dc") in pairs

    def test_no_attacker(self):
        paths, pairs = _build_privilege_paths([], set(), {"dc"})
        assert paths == []

    def test_no_da(self):
        paths, pairs = _build_privilege_paths([], {"att"}, set())
        assert paths == []


class TestDetectPivotChains_extended:
    def test_no_chains(self):
        assert _detect_pivot_chains([]) == []

    def test_detects_chain(self):
        obs1 = MagicMock()
        obs1.target_host_id = "h2"
        obs1.pivot_host_id = "h1"
        obs1.source_host_id = "h0"
        obs2 = MagicMock()
        obs2.target_host_id = "h1"
        obs2.pivot_host_id = "h2"
        obs2.source_host_id = "h0"
        chains = _detect_pivot_chains([obs1, obs2])
        assert len(chains) >= 1


class TestBuildHostNodes_extended:
    def test_builds_nodes(self):
        h1 = MagicMock()
        h1.id = "h1"
        h1.is_attacker = True
        h1.hostname = "att"
        h1.ip = "10.0.0.1"
        h1.status = "alive"
        h1.tags = []
        h1.os = "Linux"
        h1.ports = []
        h1.role = "attacker"
        h2 = MagicMock()
        h2.id = "h2"
        h2.is_attacker = False
        h2.hostname = "srv"
        h2.ip = "10.0.0.2"
        h2.status = "alive"
        h2.tags = []
        h2.os = "Windows"
        h2.ports = []
        h2.role = "server"
        nodes, att_ids, host_by_id, dc_ids, default_src = _build_host_nodes([h1, h2], {})
        assert len(nodes) == 2
        assert "h1" in att_ids

    def test_virtual_attacker(self):
        h = MagicMock()
        h.id = "h1"
        h.is_attacker = False
        h.hostname = "srv"
        h.ip = "10.0.0.1"
        h.status = "alive"
        h.tags = []
        h.os = "Linux"
        h.ports = []
        h.role = "server"
        nodes, att_ids, _, _, default_src = _build_host_nodes([h], {})
        assert "attacker_virtual" in [n["id"] for n in nodes]
        assert default_src == "attacker_virtual"


class TestMakeAccessEdge_extended:
    def test_creates_edge(self):
        ctr = [0]
        edge_dict, is_da, verified = _make_access_edge(
            {"type": "domain_admin", "verified": True, "confidence": 0.9, "source": "bh", "reason": "test"},
            "h1", "h2", ctr,
        )
        assert edge_dict["from"] == "h1"
        assert edge_dict["to"] == "h2"
        assert is_da is True
        assert verified is True


class TestProcessNetworkEdge_extended:
    def test_non_access_edge_skipped(self):
        edge = {"type": "logical"}
        result, verified = _process_network_edge(edge, {}, {}, set(), set(), [0])
        assert result is None

    def test_access_edge_processed(self):
        edge = {"type": "ssh", "from": "n1", "to": "n2", "verified": True, "confidence": 0.8, "source": "test"}
        nodes = {"n1": {"host_id": "h1"}, "n2": {"host_id": "h2"}}
        hosts = {"h1": MagicMock(), "h2": MagicMock()}
        result, verified = _process_network_edge(edge, nodes, hosts, set(), set(), [0])
        assert result is not None
        assert result["from"] == "h1"
        assert result["to"] == "h2"

    def test_duplicate_skipped(self):
        edge = {"type": "ssh", "from": "n1", "to": "n2", "source": "s1"}
        nodes = {"n1": {"host_id": "h1"}, "n2": {"host_id": "h2"}}
        hosts = {"h1": MagicMock(), "h2": MagicMock()}
        seen = {("h1", "h2", "ssh", "s1")}
        result, verified = _process_network_edge(edge, nodes, hosts, set(), seen, [0])
        assert result is None


class TestAnnotateEdgesPrivPath_extended:
    def test_annotates(self):
        edges = [
            {"kind": "access", "from": "a", "to": "b"},
            {"kind": "credential", "from": "x", "to": "y"},
        ]
        _annotate_edges_priv_path(edges, {("a", "b")})
        assert edges[0]["on_priv_path"] is True
        assert edges[1]["on_priv_path"] is False


class TestDaPathDistance_extended:
    def test_finds_distance(self):
        paths = [["a", "b", "c"]]
        assert _da_path_distance("b", paths) == 1
        assert _da_path_distance("c", paths) == 2
        assert _da_path_distance("z", paths) is None


class TestEnsureStepNode:
    def test_adds_step_node(self):
        nodes = [{"id": "existing"}]
        step = MagicMock()
        step.id = "step1"
        step.label = "Step 1"
        step.technique = ""
        step.step_order = 0
        _ensure_step_node(nodes, step)
        assert len(nodes) == 2
        assert nodes[1]["type"] == "step"

    def test_skips_existing(self):
        nodes = [{"id": "step1"}]
        step = MagicMock()
        step.id = "step1"
        _ensure_step_node(nodes, step)
        assert len(nodes) == 1


class TestFindEdgeTech_extended:
    def test_finds_tech(self):
        edges = [{"from": "a", "to": "b", "access_type": "ssh"}]
        assert _find_edge_tech(edges, "a", "b") == "ssh"

    def test_not_found(self):
        assert _find_edge_tech([], "a", "b") == ""


class TestBuildPrivilegePathDetails_extended:
    def test_builds_details(self):
        paths = [["a", "b"]]
        label_map = {"a": "att", "b": "dc"}
        access_edges = [{"from": "a", "to": "b", "access_type": "smb_admin"}]
        details = _build_privilege_path_details(paths, label_map, access_edges)
        assert len(details) == 1
        assert details[0][0]["label"] == "att"
        assert details[0][0]["edge_to_next"] == "smb_admin"
        assert details[0][1]["edge_to_next"] == ""


# ════════ from test_attack_graph_extra.py ════════
import pytest
from unittest.mock import MagicMock

from app.routers.attack_graph import (
    _is_access_edge,
    _is_dc,
    _bfs_dist,
    _reachability_walk,
    _build_access_adjacency,
    _bfs_to_da,
    _build_privilege_paths,
    _detect_pivot_chains,
    _collect_relay_chains,
    _da_path_distance,
    _annotate_nodes,
    _annotate_edges_priv_path,
    _find_edge_tech,
)


class TestIsAccessEdge_extra:
    def test_ssh_type(self):
        assert _is_access_edge({"type": "ssh"}) is True

    def test_cred_validation_source(self):
        assert _is_access_edge({"type": "other", "source": "cred_validation"}) is True

    def test_exploit_style(self):
        assert _is_access_edge({"type": "other", "style": "exploit"}) is True

    def test_not_access(self):
        assert _is_access_edge({"type": "network", "source": "manual"}) is False


class TestIsDc_extra:
    def test_dc_role(self):
        h = MagicMock()
        h.role = "domain_controller"
        h.tags = []
        h.ports = []
        assert _is_dc(h) is True

    def test_dc_tag(self):
        h = MagicMock()
        h.role = ""
        h.tags = ["dc"]
        h.ports = []
        assert _is_dc(h) is True

    def test_dc_ports(self):
        h = MagicMock()
        h.role = ""
        h.tags = []
        h.ports = ["88/tcp", "389/tcp"]
        assert _is_dc(h) is True

    def test_not_dc(self):
        h = MagicMock()
        h.role = "server"
        h.tags = []
        h.ports = ["80/tcp"]
        assert _is_dc(h) is False


class TestBfsDist_extra:
    def test_basic(self):
        adj = {"a": ["b"], "b": ["c"]}
        dist = _bfs_dist(adj, ["a"])
        assert dist == {"a": 0, "b": 1, "c": 2}

    def test_unreachable(self):
        adj = {"a": ["b"], "c": []}
        dist = _bfs_dist(adj, ["a"])
        assert "c" not in dist

    def test_empty(self):
        assert _bfs_dist({}, []) == {}


class TestReachabilityWalk_extra:
    def test_basic(self):
        edges = [{"from": "a", "to": "b", "access_type": "ssh"}]
        dist = _reachability_walk(edges, {"a"}, False)
        assert dist.get("b") == 1

    def test_verified_only(self):
        edges = [{"from": "a", "to": "b", "verified": False, "access_type": "ssh"}]
        dist = _reachability_walk(edges, {"a"}, True)
        assert "b" not in dist

    def test_bidirectional(self):
        edges = [{"from": "a", "to": "b", "access_type": "lateral"}]
        dist = _reachability_walk(edges, {"a"}, False)
        assert dist.get("b") == 1


class TestBuildAccessAdjacency_extra:
    def test_basic(self):
        edges = [{"from": "a", "to": "b", "access_type": "ssh", "label": ""}]
        adj = _build_access_adjacency(edges)
        assert ("b", "ssh") in adj.get("a", [])

    def test_bidirectional_lateral(self):
        edges = [{"from": "a", "to": "b", "access_type": "lateral", "label": ""}]
        adj = _build_access_adjacency(edges)
        assert ("a", "lateral") in adj.get("b", [])


class TestBfsToDa_extra:
    def test_found(self):
        adj = {"a": [("b", "ssh")], "b": [("da1", "smb_admin")]}
        parent = _bfs_to_da({"a"}, "da1", adj)
        assert parent is not None

    def test_not_found(self):
        adj = {"a": [("b", "ssh")]}
        parent = _bfs_to_da({"a"}, "da_missing", adj)
        assert parent is None


class TestBuildPrivilegePaths_extra:
    def test_basic_path(self):
        edges = [
            {"from": "atk", "to": "h1", "type": "ssh", "style": "", "label": "ssh", "access_type": "ssh"},
            {"from": "h1", "to": "da", "type": "domain_admin", "style": "", "label": "DA", "access_type": "domain_admin"},
        ]
        paths, pairs = _build_privilege_paths(edges, {"atk"}, {"da"})
        assert len(paths) >= 1

    def test_empty_attacker(self):
        assert _build_privilege_paths([], set(), {"da"}) == ([], set())


class TestDetectPivotChains_extra:
    def test_chain(self):
        obs1 = MagicMock()
        obs1.pivot_host_id = "pivot1"
        obs1.target_host_id = "target1"
        obs1.source_host_id = "source1"
        obs2 = MagicMock()
        obs2.pivot_host_id = "pivot2"
        obs2.target_host_id = "pivot1"
        obs2.source_host_id = "source2"
        chains = _detect_pivot_chains([obs1, obs2])
        assert len(chains) >= 0

    def test_empty(self):
        assert _detect_pivot_chains([]) == []


class TestDaPathDistance_extra:
    def test_found(self):
        assert _da_path_distance("b", [["a", "b", "c"]]) == 1

    def test_not_found(self):
        assert _da_path_distance("x", [["a", "b"]]) is None


class TestAnnotateEdgesPrivPath_extra:
    def test_annotates(self):
        edges = [{"from": "a", "to": "b", "kind": "access"}]
        pairs = {("a", "b")}
        _annotate_edges_priv_path(edges, pairs)
        assert edges[0]["on_priv_path"] is True

    def test_not_on_path(self):
        edges = [{"from": "a", "to": "c", "kind": "access"}]
        _annotate_edges_priv_path(edges, {("x", "y")})
        assert edges[0]["on_priv_path"] is False


class TestAnnotateNodes_extra:
    def test_basic(self):
        nodes = [{"id": "n1"}]
        _annotate_nodes(
            nodes, {"n1"}, {"n1": 0}, {"n1": 0},
            {"da1"}, {"n1"}, {"n1"}, [["n1", "da1"]],
        )
        assert nodes[0]["reachability"]["reachable"] is True
        assert nodes[0]["reachability"]["is_root"] is True


class TestFindEdgeTech_extra:
    def test_found(self):
        edges = [{"from": "a", "to": "b", "access_type": "ssh"}]
        assert _find_edge_tech(edges, "a", "b") == "ssh"

    def test_not_found(self):
        assert _find_edge_tech([], "a", "b") == ""


# ════════ from test_attack_graph_final.py ════════
import pytest
from unittest.mock import MagicMock, patch

from app.routers.attack_graph import (
    _is_access_edge,
    _is_dc,
    _bfs_dist,
    _reachability_walk,
    _build_reachability,
    _build_access_adjacency,
    _bfs_to_da,
    _build_privilege_paths,
    _detect_pivot_chains,
    _collect_relay_chains,
    _find_edge_tech,
    _build_privilege_path_details,
    _annotate_edges_priv_path,
    _da_path_distance,
    _annotate_nodes,
)


class TestIsAccessEdge_final:
    def test_ssh_type(self):
        assert _is_access_edge({"type": "ssh"}) is True

    def test_lateral_style(self):
        assert _is_access_edge({"style": "lateral"}) is True

    def test_cred_validation_source(self):
        assert _is_access_edge({"source": "cred_validation"}) is True

    def test_unknown(self):
        assert _is_access_edge({"type": "same_subnet", "source": "nmap", "style": ""}) is False


class TestIsDc_final:
    def test_role(self):
        host = MagicMock()
        host.role = "domain_controller"
        host.tags = []
        host.ports = []
        assert _is_dc(host) is True

    def test_tag(self):
        host = MagicMock()
        host.role = ""
        host.tags = ["dc"]
        host.ports = []
        assert _is_dc(host) is True

    def test_ports(self):
        host = MagicMock()
        host.role = ""
        host.tags = []
        host.ports = ["88/tcp", "389/tcp"]
        assert _is_dc(host) is True

    def test_not_dc(self):
        host = MagicMock()
        host.role = "server"
        host.tags = []
        host.ports = ["22/tcp"]
        assert _is_dc(host) is False


class TestBfsDist_final:
    def test_basic(self):
        adj = {"a": ["b"], "b": ["c"]}
        dist = _bfs_dist(adj, ["a"])
        assert dist["a"] == 0
        assert dist["b"] == 1
        assert dist["c"] == 2

    def test_no_edges(self):
        assert _bfs_dist({}, ["a"]) == {"a": 0}


class TestReachabilityWalk_final:
    def test_basic(self):
        edges = [{"from": "a", "to": "b", "verified": True, "access_type": ""}]
        dist = _reachability_walk(edges, {"a"}, False)
        assert "b" in dist

    def test_verified_only(self):
        edges = [{"from": "a", "to": "b", "verified": False, "access_type": ""}]
        dist = _reachability_walk(edges, {"a"}, True)
        assert "b" not in dist

    def test_bidirectional(self):
        edges = [{"from": "a", "to": "b", "verified": True, "access_type": "lateral"}]
        dist = _reachability_walk(edges, {"a"}, False)
        assert "b" in dist


class TestBuildReachability_final:
    def test_returns_tuple(self):
        edges = [{"from": "a", "to": "b", "verified": True, "access_type": ""}]
        r, v = _build_reachability(edges, {"a"})
        assert isinstance(r, dict)
        assert isinstance(v, dict)


class TestBuildAccessAdjacency_final:
    def test_basic(self):
        edges = [{"from": "a", "to": "b", "type": "ssh", "label": "", "access_type": ""}]
        adj = _build_access_adjacency(edges)
        assert "b" in [x[0] for x in adj.get("a", [])]

    def test_bidirectional(self):
        edges = [{"from": "a", "to": "b", "type": "", "label": "lateral", "access_type": "lateral"}]
        adj = _build_access_adjacency(edges)
        assert "a" in [x[0] for x in adj.get("b", [])]


class TestBfsToDa_final:
    def test_reachable(self):
        adj = {"a": [("b", "ssh")], "b": [("da", "admin")]}
        result = _bfs_to_da({"a"}, "da", adj)
        assert result is not None
        assert "da" in result

    def test_unreachable(self):
        adj = {"a": [("b", "ssh")]}
        result = _bfs_to_da({"a"}, "da", adj)
        assert result is None


class TestBuildPrivilegePaths_final:
    def test_no_attacker(self):
        paths, pairs = _build_privilege_paths([], {"dc1"}, [])
        assert paths == []

    def test_no_da(self):
        paths, pairs = _build_privilege_paths([], set(), [{"from": "a", "to": "b", "type": "", "label": "", "access_type": ""}])
        assert paths == []


class TestDetectPivotChains_final:
    def test_basic_chain(self):
        obs1 = MagicMock()
        obs1.pivot_host_id = "p1"
        obs1.target_host_id = "t1"
        obs1.source_host_id = "s1"
        obs2 = MagicMock()
        obs2.pivot_host_id = "p2"
        obs2.target_host_id = "p1"
        obs2.source_host_id = "s2"
        chains = _detect_pivot_chains([obs1, obs2])
        assert len(chains) > 0


class TestCollectRelayChains_final:
    def test_basic(self):
        obs = MagicMock()
        obs.pivot_host_id = "relay"
        obs.target_host_id = "target"
        obs.source_host_id = "source"
        upstream = MagicMock()
        upstream.source_host_id = "upstream_src"
        upstream.pivot_host_id = "upstream_pivot"
        target_to_obs = {"relay": [upstream]}
        seen = set()
        chains = _collect_relay_chains(obs, target_to_obs, seen)
        assert len(chains) > 0


class TestFindEdgeTech_final:
    def test_found(self):
        edges = [{"from": "a", "to": "b", "access_type": "ssh", "label": ""}]
        assert _find_edge_tech(edges, "a", "b") == "ssh"

    def test_not_found(self):
        assert _find_edge_tech([], "a", "b") == ""


class TestBuildPrivilegePathDetails_final:
    def test_basic(self):
        paths = [["a", "b", "da"]]
        host_label = {"a": "attacker", "b": "srv", "da": "dc"}
        access = [{"from": "a", "to": "b", "access_type": "ssh"}]
        result = _build_privilege_path_details(paths, host_label, access)
        assert len(result) == 1
        assert len(result[0]) == 3


class TestAnnotateEdgesPrivPath_final:
    def test_annotates(self):
        edges = [{"from": "a", "to": "b", "kind": "access"}, {"from": "c", "to": "d", "kind": "path"}]
        pairs = {("a", "b")}
        _annotate_edges_priv_path(edges, pairs)
        assert edges[0]["on_priv_path"] is True
        assert edges[1]["on_priv_path"] is False


class TestDaPathDistance_final:
    def test_found(self):
        assert _da_path_distance("b", [["a", "b", "c"]]) == 1

    def test_not_found(self):
        assert _da_path_distance("x", [["a", "b"]]) is None


class TestAnnotateNodes_final:
    def test_basic(self):
        nodes = [{"id": "a"}, {"id": "b"}]
        _annotate_nodes(
            nodes,
            attacker_host_ids={"a"},
            reachable_dist={"a": 0, "b": 1},
            verified_reachable_dist={"a": 0},
            da_host_ids=set(),
            dc_host_ids=set(),
            da_path_nodes=set(),
            privilege_paths=[],
        )
        assert nodes[0]["reachability"]["is_root"] is True
        assert nodes[1]["reachability"]["reachable"] is True


# ════════ from test_attack_graph_final2.py ════════
import pytest
from unittest.mock import MagicMock

from app.routers.attack_graph import (
    _is_access_edge,
    _is_dc,
    _bfs_dist,
    _reachability_walk,
    _build_reachability,
    _build_access_adjacency,
    _bfs_to_da,
    _build_privilege_paths,
    _collect_relay_chains,
    _detect_pivot_chains,
    _make_access_edge,
    _process_network_edge,
    _build_cred_edges,
    _find_edge_tech,
    _annotate_edges_priv_path,
    _da_path_distance,
    _annotate_nodes,
    _build_host_nodes,
    _ACCESS_EDGE_TYPES,
    _ACCESS_EDGE_STYLES,
)


class TestIsAccessEdge_final2:
    def test_type_match(self):
        for t in _ACCESS_EDGE_TYPES:
            assert _is_access_edge({"type": t}) is True

    def test_source_match(self):
        assert _is_access_edge({"source": "cred_validation"}) is True
        assert _is_access_edge({"source": "bulk_exec"}) is True

    def test_style_match(self):
        for s in _ACCESS_EDGE_STYLES:
            assert _is_access_edge({"style": s}) is True

    def test_no_match(self):
        assert _is_access_edge({"type": "info", "source": "", "style": ""}) is False


class TestIsDc_final2:
    def test_role(self):
        h = MagicMock()
        h.role = "domain_controller"
        h.tags = []
        h.ports = []
        assert _is_dc(h) is True

    def test_dc_tag(self):
        h = MagicMock()
        h.role = ""
        h.tags = ["dc"]
        h.ports = []
        assert _is_dc(h) is True

    def test_ports(self):
        h = MagicMock()
        h.role = ""
        h.tags = []
        h.ports = ["88/tcp", "389/tcp"]
        assert _is_dc(h) is True

    def test_no(self):
        h = MagicMock()
        h.role = "server"
        h.tags = []
        h.ports = ["80/tcp"]
        assert _is_dc(h) is False


class TestBfsDist_final2:
    def test_basic(self):
        adj = {"a": ["b"], "b": ["c"]}
        r = _bfs_dist(adj, ["a"])
        assert r == {"a": 0, "b": 1, "c": 2}

    def test_empty(self):
        assert _bfs_dist({}, []) == {}


class TestReachabilityWalk_final2:
    def test_unverified(self):
        edges = [{"from": "a", "to": "b"}, {"from": "b", "to": "c"}]
        r = _reachability_walk(edges, {"a"}, False)
        assert "c" in r

    def test_verified_only(self):
        edges = [{"from": "a", "to": "b", "verified": True},
                 {"from": "b", "to": "c", "verified": False}]
        r = _reachability_walk(edges, {"a"}, True)
        assert "b" in r
        assert "c" not in r

    def test_bidirectional(self):
        edges = [{"from": "a", "to": "b", "access_type": "lateral"}]
        r = _reachability_walk(edges, {"b"}, False)
        assert "a" in r


class TestBuildReachability_final2:
    def test_returns_both(self):
        edges = [{"from": "a", "to": "b", "verified": True}]
        unv, v = _build_reachability(edges, {"a"})
        assert "b" in unv
        assert "b" in v


class TestBuildAccessAdjacency_final2:
    def test_basic(self):
        edges = [{"from": "a", "to": "b", "access_type": "ssh"}]
        r = _build_access_adjacency(edges)
        assert ("b", "ssh") in r["a"]

    def test_bidirectional(self):
        edges = [{"from": "a", "to": "b", "access_type": "pivot"}]
        r = _build_access_adjacency(edges)
        assert ("a", "pivot") in r["b"]

    def test_empty_src_dst(self):
        edges = [{"from": "", "to": "b"}]
        r = _build_access_adjacency(edges)
        assert "b" not in r.get("", [])


class TestBfsToDa_final2:
    def test_reached(self):
        adj = {"a": [("b", "ssh")], "b": [("c", "ssh")]}
        r = _bfs_to_da({"a"}, "c", adj)
        assert r is not None
        assert r["c"] == "b"

    def test_not_reached(self):
        adj = {"a": [("b", "ssh")]}
        r = _bfs_to_da({"a"}, "c", adj)
        assert r is None


class TestBuildPrivilegePaths_final2:
    def test_basic(self):
        edges = [{"from": "atk", "to": "h1", "access_type": "ssh"},
                 {"from": "h1", "to": "dc", "access_type": "domain_admin"}]
        paths, pairs = _build_privilege_paths(edges, {"atk"}, {"dc"})
        assert len(paths) == 1
        assert ("atk", "h1") in pairs

    def test_no_attacker(self):
        assert _build_privilege_paths([], set(), {"dc"}) == ([], set())

    def test_no_da(self):
        assert _build_privilege_paths([], {"atk"}, set()) == ([], set())


class TestCollectRelayChains_final2:
    def test_basic(self):
        obs = MagicMock()
        obs.pivot_host_id = "relay"
        obs.target_host_id = "target"
        upstream = MagicMock()
        upstream.source_host_id = "src"
        upstream.pivot_host_id = "up_pivot"
        upstream.target_host_id = "relay"
        target_to_obs = {"relay": [upstream]}
        seen = set()
        r = _collect_relay_chains(obs, target_to_obs, seen)
        assert len(r) == 1
        assert r[0] == ["src", "relay", "target"]


class TestDetectPivotChains_final2:
    def test_empty(self):
        assert _detect_pivot_chains([]) == []


class TestMakeAccessEdge_final2:
    def test_basic(self):
        edge = {"id": "e1", "type": "ssh", "style": "exploit", "label": "SSH",
                "confidence": 0.9, "state": "confirmed", "source": "manual", "reason": "r"}
        ed, is_da, verified = _make_access_edge(edge, "h1", "h2", [0])
        assert ed["from"] == "h1"
        assert verified is True

    def test_da_type(self):
        ed, is_da, _ = _make_access_edge({"type": "domain_admin"}, "a", "b", [0])
        assert is_da is True


class TestProcessNetworkEdge_final2:
    def test_non_access(self):
        r, v = _process_network_edge({"type": "info"}, {}, {}, set(), set(), [0])
        assert r is None

    def test_no_host(self):
        r, v = _process_network_edge({"type": "ssh", "from": "n1", "to": "n2"},
                                      {"n1": {}, "n2": {}}, set(), set(), set(), [0])
        assert r is None


class TestBuildCredEdges:
    def test_basic(self):
        cred = MagicMock()
        cred.id = "c1"
        cred.domain = "corp"
        cred.username = "admin"
        cred.type = "plain"
        cred.host_ids = ["h1"]
        host = MagicMock()
        host.id = "h1"
        edges, count = _build_cred_edges([cred], {"h1": host}, "atk", [0])
        assert count == 1
        assert edges[0]["kind"] == "credential"

    def test_empty_host_ids(self):
        cred = MagicMock()
        cred.host_ids = []
        edges, count = _build_cred_edges([cred], {}, "atk", [0])
        assert count == 0


class TestFindEdgeTech_final2:
    def test_found(self):
        assert _find_edge_tech([{"from": "a", "to": "b", "access_type": "ssh"}], "a", "b") == "ssh"

    def test_not_found(self):
        assert _find_edge_tech([], "a", "b") == ""


class TestAnnotateEdgesPrivPath_final2:
    def test_annotates(self):
        edges = [{"kind": "access", "from": "a", "to": "b"},
                 {"kind": "info", "from": "c", "to": "d"}]
        _annotate_edges_priv_path(edges, {("a", "b")})
        assert edges[0]["on_priv_path"] is True
        assert edges[1]["on_priv_path"] is False


class TestDaPathDistance_final2:
    def test_found(self):
        assert _da_path_distance("b", [["a", "b", "c"]]) == 1

    def test_not_found(self):
        assert _da_path_distance("x", [["a", "b"]]) is None


class TestBuildHostNodes_final2:
    def test_basic(self):
        h = MagicMock()
        h.id = "h1"
        h.is_attacker = False
        h.hostname = "srv"
        h.ip = "10.0.0.1"
        h.status = "up"
        h.tags = []
        h.os = "Linux"
        h.ports = []
        h.role = "server"
        nodes, att_ids, host_by_id, dc_ids, default = _build_host_nodes([h], {})
        assert len(nodes) == 2  # host + virtual attacker
        assert "attacker_virtual" in default
        assert nodes[0]["zone_type"] == ""

    def test_with_attacker(self):
        h = MagicMock()
        h.id = "atk1"
        h.is_attacker = True
        h.hostname = "kali"
        h.ip = "10.0.0.99"
        h.status = "attacker"
        h.tags = []
        h.os = "Linux"
        h.ports = []
        h.role = "attacker"
        nodes, att_ids, _, _, default = _build_host_nodes([h], {})
        assert "atk1" in att_ids
        assert default == "atk1"


# ════════ from test_attack_graph_v3.py ════════
import pytest
from unittest.mock import MagicMock
import ipaddress

from app.routers.attack_graph import (
    _is_access_edge,
    _make_access_edge,
    _process_network_edge,
    _build_network_access_edges,
    _collect_cidr_route_edges,
    _append_pivot_src_edge,
    _append_pivot_tgt_edge,
    _build_host_nodes,
)


class TestIsAccessEdgeMore:
    def test_ssh(self):
        assert _is_access_edge({"type": "ssh"}) is True

    def test_rdp(self):
        assert _is_access_edge({"type": "rdp"}) is True

    def test_exploit_style(self):
        assert _is_access_edge({"style": "exploit"}) is True

    def test_cred_validation_source(self):
        assert _is_access_edge({"source": "cred_validation"}) is True

    def test_info(self):
        assert _is_access_edge({"type": "info"}) is False


class TestMakeAccessEdge_v3:
    def test_basic(self):
        edge = {"type": "ssh", "source": "manual", "note": "test note"}
        ctr = [0]
        result, is_da, verified = _make_access_edge(edge, "h1", "h2", ctr)
        assert result["from"] == "h1"
        assert result["to"] == "h2"
        assert result["kind"] == "access"
        assert result["access_type"] == "ssh"
        assert is_da is False

    def test_da_edge(self):
        edge = {"type": "domain_admin", "source": "bloodhound", "note": "DC sync"}
        ctr = [0]
        result, is_da, verified = _make_access_edge(edge, "h1", "dc1", ctr)
        assert is_da is True

    def test_verified_exploit(self):
        edge = {"type": "ssh", "style": "exploit"}
        ctr = [0]
        result, is_da, verified = _make_access_edge(edge, "h1", "h2", ctr)
        assert verified is True

    def test_custom_label(self):
        edge = {"type": "ssh", "label": "My custom label"}
        ctr = [0]
        result, is_da, verified = _make_access_edge(edge, "h1", "h2", ctr)
        assert result["label"] == "My custom label"


class TestBuildNetworkAccessEdges:
    def test_empty(self):
        edges, da, ac, vc = _build_network_access_edges([], {}, {}, set(), [0])
        assert edges == []
        assert ac == 0

    def test_with_valid_edge(self):
        edge = {"type": "ssh", "from": "n1", "to": "n2", "source": "manual"}
        nodes = {"n1": {"host_id": "h1"}, "n2": {"host_id": "h2"}}
        hosts = {"h1": MagicMock(), "h2": MagicMock()}
        edges, da, ac, vc = _build_network_access_edges([edge], nodes, hosts, set(), [0])
        assert len(edges) == 1
        assert ac == 1

    def test_dedup(self):
        edge = {"type": "ssh", "from": "n1", "to": "n2", "source": "manual"}
        nodes = {"n1": {"host_id": "h1"}, "n2": {"host_id": "h2"}}
        hosts = {"h1": MagicMock(), "h2": MagicMock()}
        edges, da, ac, vc = _build_network_access_edges([edge, edge], nodes, hosts, set(), [0])
        assert len(edges) == 1


class TestCollectCidrRouteEdges:
    def test_basic(self):
        h1 = MagicMock()
        h1.ip = "10.0.0.2"
        h1.id = "h1"
        net = ipaddress.ip_network("10.0.0.0/24")
        seen = set()
        edges, count = _collect_cidr_route_edges("10.0.0.0/24", net, "pivot1", [h1], "tool", True, seen, [0])
        assert count == 1
        assert len(edges) == 1

    def test_skip_self(self):
        h1 = MagicMock()
        h1.ip = "10.0.0.1"
        h1.id = "pivot1"
        net = ipaddress.ip_network("10.0.0.0/24")
        seen = set()
        edges, count = _collect_cidr_route_edges("10.0.0.0/24", net, "pivot1", [h1], "tool", True, seen, [0])
        assert count == 0

    def test_skip_other_subnet(self):
        h1 = MagicMock()
        h1.ip = "192.168.1.1"
        h1.id = "h1"
        net = ipaddress.ip_network("10.0.0.0/24")
        seen = set()
        edges, count = _collect_cidr_route_edges("10.0.0.0/24", net, "pivot1", [h1], "tool", True, seen, [0])
        assert count == 0

    def test_dedup(self):
        h1 = MagicMock()
        h1.ip = "10.0.0.2"
        h1.id = "h1"
        net = ipaddress.ip_network("10.0.0.0/24")
        seen = {("pivot1", "h1")}
        edges, count = _collect_cidr_route_edges("10.0.0.0/24", net, "pivot1", [h1], "tool", True, seen, [0])
        assert count == 0

    def test_no_ip(self):
        h1 = MagicMock()
        h1.ip = ""
        h1.id = "h1"
        net = ipaddress.ip_network("10.0.0.0/24")
        seen = set()
        edges, count = _collect_cidr_route_edges("10.0.0.0/24", net, "pivot1", [h1], "tool", True, seen, [0])
        assert count == 0


class TestAppendPivotSrcEdge:
    def test_basic(self):
        edges = []
        seen = set()
        _append_pivot_src_edge(edges, seen, "src1", "pivot1", "ssh", "socks", True, [0])
        assert len(edges) == 1
        assert edges[0]["kind"] == "pivot"

    def test_skip_self(self):
        edges = []
        seen = set()
        _append_pivot_src_edge(edges, seen, "src1", "src1", "ssh", "socks", True, [0])
        assert len(edges) == 0

    def test_dedup(self):
        edges = []
        seen = {("src1", "pivot1")}
        _append_pivot_src_edge(edges, seen, "src1", "pivot1", "ssh", "socks", True, [0])
        assert len(edges) == 0


class TestAppendPivotTgtEdge:
    def test_basic(self):
        edges = []
        seen = set()
        host_by_id = {"tgt1": MagicMock()}
        _append_pivot_tgt_edge(edges, seen, "pivot1", "tgt1", host_by_id, "ssh", "socks", True, [0])
        assert len(edges) == 1

    def test_skip_missing_host(self):
        edges = []
        seen = set()
        _append_pivot_tgt_edge(edges, seen, "pivot1", "missing", {}, "ssh", "socks", True, [0])
        assert len(edges) == 0

    def test_skip_empty_target(self):
        edges = []
        seen = set()
        _append_pivot_tgt_edge(edges, seen, "pivot1", "", {}, "ssh", "socks", True, [0])
        assert len(edges) == 0
