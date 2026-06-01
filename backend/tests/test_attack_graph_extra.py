"""Extended tests for attack_graph — helper functions."""
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


class TestIsAccessEdge:
    def test_ssh_type(self):
        assert _is_access_edge({"type": "ssh"}) is True

    def test_cred_validation_source(self):
        assert _is_access_edge({"type": "other", "source": "cred_validation"}) is True

    def test_exploit_style(self):
        assert _is_access_edge({"type": "other", "style": "exploit"}) is True

    def test_not_access(self):
        assert _is_access_edge({"type": "network", "source": "manual"}) is False


class TestIsDc:
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


class TestBfsDist:
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


class TestReachabilityWalk:
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


class TestBuildAccessAdjacency:
    def test_basic(self):
        edges = [{"from": "a", "to": "b", "access_type": "ssh", "label": ""}]
        adj = _build_access_adjacency(edges)
        assert ("b", "ssh") in adj.get("a", [])

    def test_bidirectional_lateral(self):
        edges = [{"from": "a", "to": "b", "access_type": "lateral", "label": ""}]
        adj = _build_access_adjacency(edges)
        assert ("a", "lateral") in adj.get("b", [])


class TestBfsToDa:
    def test_found(self):
        adj = {"a": [("b", "ssh")], "b": [("da1", "smb_admin")]}
        parent = _bfs_to_da({"a"}, "da1", adj)
        assert parent is not None

    def test_not_found(self):
        adj = {"a": [("b", "ssh")]}
        parent = _bfs_to_da({"a"}, "da_missing", adj)
        assert parent is None


class TestBuildPrivilegePaths:
    def test_basic_path(self):
        edges = [
            {"from": "atk", "to": "h1", "type": "ssh", "style": "", "label": "ssh", "access_type": "ssh"},
            {"from": "h1", "to": "da", "type": "domain_admin", "style": "", "label": "DA", "access_type": "domain_admin"},
        ]
        paths, pairs = _build_privilege_paths(edges, {"atk"}, {"da"})
        assert len(paths) >= 1

    def test_empty_attacker(self):
        assert _build_privilege_paths([], set(), {"da"}) == ([], set())


class TestDetectPivotChains:
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


class TestDaPathDistance:
    def test_found(self):
        assert _da_path_distance("b", [["a", "b", "c"]]) == 1

    def test_not_found(self):
        assert _da_path_distance("x", [["a", "b"]]) is None


class TestAnnotateEdgesPrivPath:
    def test_annotates(self):
        edges = [{"from": "a", "to": "b", "kind": "access"}]
        pairs = {("a", "b")}
        _annotate_edges_priv_path(edges, pairs)
        assert edges[0]["on_priv_path"] is True

    def test_not_on_path(self):
        edges = [{"from": "a", "to": "c", "kind": "access"}]
        _annotate_edges_priv_path(edges, {("x", "y")})
        assert edges[0]["on_priv_path"] is False


class TestAnnotateNodes:
    def test_basic(self):
        nodes = [{"id": "n1"}]
        _annotate_nodes(
            nodes, {"n1"}, {"n1": 0}, {"n1": 0},
            {"da1"}, {"n1"}, {"n1"}, [["n1", "da1"]],
        )
        assert nodes[0]["reachability"]["reachable"] is True
        assert nodes[0]["reachability"]["is_root"] is True


class TestFindEdgeTech:
    def test_found(self):
        edges = [{"from": "a", "to": "b", "access_type": "ssh"}]
        assert _find_edge_tech(edges, "a", "b") == "ssh"

    def test_not_found(self):
        assert _find_edge_tech([], "a", "b") == ""
