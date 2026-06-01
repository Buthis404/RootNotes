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


class TestIsAccessEdge:
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


class TestIsDc:
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


class TestBfsDist:
    def test_basic(self):
        adj = {"a": ["b"], "b": ["c"]}
        r = _bfs_dist(adj, ["a"])
        assert r == {"a": 0, "b": 1, "c": 2}

    def test_empty(self):
        assert _bfs_dist({}, []) == {}


class TestReachabilityWalk:
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


class TestBuildReachability:
    def test_returns_both(self):
        edges = [{"from": "a", "to": "b", "verified": True}]
        unv, v = _build_reachability(edges, {"a"})
        assert "b" in unv
        assert "b" in v


class TestBuildAccessAdjacency:
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


class TestBfsToDa:
    def test_reached(self):
        adj = {"a": [("b", "ssh")], "b": [("c", "ssh")]}
        r = _bfs_to_da({"a"}, "c", adj)
        assert r is not None
        assert r["c"] == "b"

    def test_not_reached(self):
        adj = {"a": [("b", "ssh")]}
        r = _bfs_to_da({"a"}, "c", adj)
        assert r is None


class TestBuildPrivilegePaths:
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


class TestCollectRelayChains:
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


class TestDetectPivotChains:
    def test_empty(self):
        assert _detect_pivot_chains([]) == []


class TestMakeAccessEdge:
    def test_basic(self):
        edge = {"id": "e1", "type": "ssh", "style": "exploit", "label": "SSH",
                "confidence": 0.9, "state": "confirmed", "source": "manual", "reason": "r"}
        ed, is_da, verified = _make_access_edge(edge, "h1", "h2", [0])
        assert ed["from"] == "h1"
        assert verified is True

    def test_da_type(self):
        ed, is_da, _ = _make_access_edge({"type": "domain_admin"}, "a", "b", [0])
        assert is_da is True


class TestProcessNetworkEdge:
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


class TestFindEdgeTech:
    def test_found(self):
        assert _find_edge_tech([{"from": "a", "to": "b", "access_type": "ssh"}], "a", "b") == "ssh"

    def test_not_found(self):
        assert _find_edge_tech([], "a", "b") == ""


class TestAnnotateEdgesPrivPath:
    def test_annotates(self):
        edges = [{"kind": "access", "from": "a", "to": "b"},
                 {"kind": "info", "from": "c", "to": "d"}]
        _annotate_edges_priv_path(edges, {("a", "b")})
        assert edges[0]["on_priv_path"] is True
        assert edges[1]["on_priv_path"] is False


class TestDaPathDistance:
    def test_found(self):
        assert _da_path_distance("b", [["a", "b", "c"]]) == 1

    def test_not_found(self):
        assert _da_path_distance("x", [["a", "b"]]) is None


class TestBuildHostNodes:
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
