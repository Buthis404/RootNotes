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


class TestIsAccessEdge:
    def test_ssh_type(self):
        assert _is_access_edge({"type": "ssh"}) is True

    def test_lateral_style(self):
        assert _is_access_edge({"style": "lateral"}) is True

    def test_cred_validation_source(self):
        assert _is_access_edge({"source": "cred_validation"}) is True

    def test_unknown(self):
        assert _is_access_edge({"type": "same_subnet", "source": "nmap", "style": ""}) is False


class TestIsDc:
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


class TestBfsDist:
    def test_basic(self):
        adj = {"a": ["b"], "b": ["c"]}
        dist = _bfs_dist(adj, ["a"])
        assert dist["a"] == 0
        assert dist["b"] == 1
        assert dist["c"] == 2

    def test_no_edges(self):
        assert _bfs_dist({}, ["a"]) == {"a": 0}


class TestReachabilityWalk:
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


class TestBuildReachability:
    def test_returns_tuple(self):
        edges = [{"from": "a", "to": "b", "verified": True, "access_type": ""}]
        r, v = _build_reachability(edges, {"a"})
        assert isinstance(r, dict)
        assert isinstance(v, dict)


class TestBuildAccessAdjacency:
    def test_basic(self):
        edges = [{"from": "a", "to": "b", "type": "ssh", "label": "", "access_type": ""}]
        adj = _build_access_adjacency(edges)
        assert "b" in [x[0] for x in adj.get("a", [])]

    def test_bidirectional(self):
        edges = [{"from": "a", "to": "b", "type": "", "label": "lateral", "access_type": "lateral"}]
        adj = _build_access_adjacency(edges)
        assert "a" in [x[0] for x in adj.get("b", [])]


class TestBfsToDa:
    def test_reachable(self):
        adj = {"a": [("b", "ssh")], "b": [("da", "admin")]}
        result = _bfs_to_da({"a"}, "da", adj)
        assert result is not None
        assert "da" in result

    def test_unreachable(self):
        adj = {"a": [("b", "ssh")]}
        result = _bfs_to_da({"a"}, "da", adj)
        assert result is None


class TestBuildPrivilegePaths:
    def test_no_attacker(self):
        paths, pairs = _build_privilege_paths([], {"dc1"}, [])
        assert paths == []

    def test_no_da(self):
        paths, pairs = _build_privilege_paths([], set(), [{"from": "a", "to": "b", "type": "", "label": "", "access_type": ""}])
        assert paths == []


class TestDetectPivotChains:
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


class TestCollectRelayChains:
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


class TestFindEdgeTech:
    def test_found(self):
        edges = [{"from": "a", "to": "b", "access_type": "ssh", "label": ""}]
        assert _find_edge_tech(edges, "a", "b") == "ssh"

    def test_not_found(self):
        assert _find_edge_tech([], "a", "b") == ""


class TestBuildPrivilegePathDetails:
    def test_basic(self):
        paths = [["a", "b", "da"]]
        host_label = {"a": "attacker", "b": "srv", "da": "dc"}
        access = [{"from": "a", "to": "b", "access_type": "ssh"}]
        result = _build_privilege_path_details(paths, host_label, access)
        assert len(result) == 1
        assert len(result[0]) == 3


class TestAnnotateEdgesPrivPath:
    def test_annotates(self):
        edges = [{"from": "a", "to": "b", "kind": "access"}, {"from": "c", "to": "d", "kind": "path"}]
        pairs = {("a", "b")}
        _annotate_edges_priv_path(edges, pairs)
        assert edges[0]["on_priv_path"] is True
        assert edges[1]["on_priv_path"] is False


class TestDaPathDistance:
    def test_found(self):
        assert _da_path_distance("b", [["a", "b", "c"]]) == 1

    def test_not_found(self):
        assert _da_path_distance("x", [["a", "b"]]) is None


class TestAnnotateNodes:
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
