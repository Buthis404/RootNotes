import pytest
from unittest.mock import MagicMock
from fastapi import HTTPException

from app.routers.network_map import (
    _find_node,
    _find_edge,
    _node_version,
    _edge_version,
    _region_version,
    _node_ref,
    _edge_ref,
    _clear_suppressed_auto_link,
)


class TestFindNode:
    def test_found(self):
        nodes = [{"id": "n1"}, {"id": "n2"}]
        idx, node = _find_node(nodes, "n1")
        assert idx == 0
        assert node["id"] == "n1"

    def test_not_found(self):
        with pytest.raises(HTTPException) as exc_info:
            _find_node([{"id": "n1"}], "n2")
        assert exc_info.value.status_code == 404


class TestFindEdge:
    def test_found(self):
        edges = [{"id": "e1"}, {"id": "e2"}]
        idx, edge = _find_edge(edges, "e2")
        assert idx == 1
        assert edge["id"] == "e2"

    def test_not_found(self):
        with pytest.raises(HTTPException) as exc_info:
            _find_edge([{"id": "e1"}], "e2")
        assert exc_info.value.status_code == 404


class TestVersions:
    def test_node_version_zero(self):
        assert _node_version({}) == 1

    def test_node_version_increment(self):
        assert _node_version({"version": 5}) == 6

    def test_edge_version_zero(self):
        assert _edge_version({}) == 1

    def test_edge_version_increment(self):
        assert _edge_version({"version": 3}) == 4

    def test_region_version_zero(self):
        assert _region_version({}) == 1

    def test_region_version_increment(self):
        assert _region_version({"version": 10}) == 11


class TestNodeRef:
    def test_host_id(self):
        assert _node_ref({"host_id": "h1", "ip": "10.0.0.1", "id": "n1"}) == "h1"

    def test_ip(self):
        assert _node_ref({"ip": "10.0.0.1", "id": "n1"}) == "10.0.0.1"

    def test_id(self):
        assert _node_ref({"id": "n1"}) == "n1"

    def test_none(self):
        assert _node_ref(None) == ""

    def test_empty(self):
        assert _node_ref({}) == ""


class TestEdgeRef:
    def test_basic(self):
        ref = _edge_ref({"host_id": "h1"}, {"host_id": "h2"})
        assert "h1" in ref
        assert "h2" in ref

    def test_sorted(self):
        ref = _edge_ref({"host_id": "h2"}, {"host_id": "h1"})
        assert ref == "h1::h2"

    def test_empty(self):
        assert _edge_ref(None, {"host_id": "h1"}) == ""


class TestClearSuppressedAutoLink:
    def test_removes_entry(self):
        meta = {"suppressed_auto_links": ["a::b", "c::d"]}
        _clear_suppressed_auto_link(meta, "a::b")
        assert "a::b" not in meta["suppressed_auto_links"]

    def test_removes_key_when_empty(self):
        meta = {"suppressed_auto_links": ["a::b"]}
        _clear_suppressed_auto_link(meta, "a::b")
        assert "suppressed_auto_links" not in meta

    def test_empty_ref(self):
        meta = {"suppressed_auto_links": ["a::b"]}
        _clear_suppressed_auto_link(meta, "")
        assert meta["suppressed_auto_links"] == ["a::b"]

    def test_no_key(self):
        meta = {}
        _clear_suppressed_auto_link(meta, "a::b")
        assert "suppressed_auto_links" not in meta
