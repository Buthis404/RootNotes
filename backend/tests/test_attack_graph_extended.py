"""Extended attack graph tests — helper functions and edge cases."""
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


class TestIsAccessEdge:
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


class TestIsDc:
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


class TestBfsDist:
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


class TestReachabilityWalk:
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


class TestBuildAccessAdjacency:
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


class TestBfsToDa:
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


class TestBuildPrivilegePaths:
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


class TestDetectPivotChains:
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


class TestBuildHostNodes:
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


class TestMakeAccessEdge:
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


class TestProcessNetworkEdge:
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


class TestAnnotateEdgesPrivPath:
    def test_annotates(self):
        edges = [
            {"kind": "access", "from": "a", "to": "b"},
            {"kind": "credential", "from": "x", "to": "y"},
        ]
        _annotate_edges_priv_path(edges, {("a", "b")})
        assert edges[0]["on_priv_path"] is True
        assert edges[1]["on_priv_path"] is False


class TestDaPathDistance:
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


class TestFindEdgeTech:
    def test_finds_tech(self):
        edges = [{"from": "a", "to": "b", "access_type": "ssh"}]
        assert _find_edge_tech(edges, "a", "b") == "ssh"

    def test_not_found(self):
        assert _find_edge_tech([], "a", "b") == ""


class TestBuildPrivilegePathDetails:
    def test_builds_details(self):
        paths = [["a", "b"]]
        label_map = {"a": "att", "b": "dc"}
        access_edges = [{"from": "a", "to": "b", "access_type": "smb_admin"}]
        details = _build_privilege_path_details(paths, label_map, access_edges)
        assert len(details) == 1
        assert details[0][0]["label"] == "att"
        assert details[0][0]["edge_to_next"] == "smb_admin"
        assert details[0][1]["edge_to_next"] == ""
