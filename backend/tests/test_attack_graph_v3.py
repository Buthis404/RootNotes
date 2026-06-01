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


class TestMakeAccessEdge:
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
