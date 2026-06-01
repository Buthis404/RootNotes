import pytest
from unittest.mock import MagicMock, patch

from app.routers.network_map import (
    _find_node,
    _find_edge,
    _node_version,
    _edge_version,
    _region_version,
    _node_ref,
    _edge_ref,
    _clear_suppressed_auto_link,
    _add_suppressed_auto_link,
    _sync_host_defaults,
    _now,
    AUTO_LINK_SUPPRESSIONS_KEY,
)


class TestFindNode:
    def test_found(self):
        nodes = [{"id": "n1"}, {"id": "n2"}]
        idx, node = _find_node(nodes, "n2")
        assert idx == 1
        assert node["id"] == "n2"

    def test_not_found(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            _find_node([{"id": "n1"}], "n99")


class TestFindEdge:
    def test_found(self):
        edges = [{"id": "e1"}, {"id": "e2"}]
        idx, edge = _find_edge(edges, "e1")
        assert idx == 0

    def test_not_found(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            _find_edge([], "e99")


class TestVersions:
    def test_node_version(self):
        assert _node_version({"version": 3}) == 4

    def test_node_version_missing(self):
        assert _node_version({}) == 1

    def test_edge_version(self):
        assert _edge_version({"version": 0}) == 1

    def test_region_version(self):
        assert _region_version({"version": 5}) == 6


class TestNodeRef:
    def test_with_host_id(self):
        assert _node_ref({"host_id": "h1", "ip": "10.0.0.1", "id": "n1"}) == "h1"

    def test_with_ip(self):
        assert _node_ref({"host_id": "", "ip": "10.0.0.1", "id": "n1"}) == "10.0.0.1"

    def test_with_id(self):
        assert _node_ref({"host_id": "", "ip": "", "id": "n1"}) == "n1"

    def test_none(self):
        assert _node_ref(None) == ""


class TestEdgeRef:
    def test_basic(self):
        ref = _edge_ref({"host_id": "h1"}, {"host_id": "h2"})
        assert ref != ""
        assert "::" in ref

    def test_empty_node(self):
        assert _edge_ref(None, {"host_id": "h1"}) == ""

    def test_empty_ref(self):
        assert _edge_ref({"host_id": ""}, {"host_id": ""}) == ""


class TestClearSuppressedAutoLink:
    def test_clears(self):
        meta = {AUTO_LINK_SUPPRESSIONS_KEY: ["ref1", "ref2"]}
        _clear_suppressed_auto_link(meta, "ref1")
        assert "ref1" not in meta[AUTO_LINK_SUPPRESSIONS_KEY]

    def test_removes_key_if_empty(self):
        meta = {AUTO_LINK_SUPPRESSIONS_KEY: ["ref1"]}
        _clear_suppressed_auto_link(meta, "ref1")
        assert AUTO_LINK_SUPPRESSIONS_KEY not in meta

    def test_empty_ref(self):
        meta = {}
        _clear_suppressed_auto_link(meta, "")
        assert AUTO_LINK_SUPPRESSIONS_KEY not in meta


class TestAddSuppressedAutoLink:
    def test_adds(self):
        meta = {}
        _add_suppressed_auto_link(meta, "ref1")
        assert "ref1" in meta[AUTO_LINK_SUPPRESSIONS_KEY]

    def test_dedup(self):
        meta = {AUTO_LINK_SUPPRESSIONS_KEY: ["ref1"]}
        _add_suppressed_auto_link(meta, "ref1")
        assert meta[AUTO_LINK_SUPPRESSIONS_KEY].count("ref1") == 1


class TestSyncHostDefaults:
    def test_fills_from_host(self):
        node = {"label": "", "ip": "", "ips": [], "ports": [], "status": "unknown", "notes": "", "role": None, "is_attacker": None}
        host = MagicMock()
        host.hostname = "SRV1"
        host.ip = "10.0.0.1"
        host.ips = ["10.0.0.1"]
        host.ports = ["22/tcp"]
        host.status = "up"
        host.notes = "info"
        host.role = "server"
        host.is_attacker = False
        result = _sync_host_defaults(node, host)
        assert result["label"] == "SRV1"
        assert result["ip"] == "10.0.0.1"
        assert result["status"] == "up"
        assert result["is_attacker"] is False

    def test_no_overwrite(self):
        node = {"label": "Custom", "ip": "10.0.0.2", "ips": [], "ports": [], "status": "up", "notes": "existing", "role": "dc", "is_attacker": True}
        host = MagicMock()
        host.hostname = "SRV1"
        host.ip = "10.0.0.1"
        host.ips = []
        host.ports = []
        host.status = "down"
        host.notes = ""
        host.role = "server"
        host.is_attacker = False
        result = _sync_host_defaults(node, host)
        assert result["label"] == "Custom"
        assert result["ip"] == "10.0.0.2"

    def test_no_host(self):
        node = {"id": "n1"}
        result = _sync_host_defaults(node, None)
        assert result == node
