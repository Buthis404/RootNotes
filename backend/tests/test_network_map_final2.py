import pytest
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
    _add_suppressed_auto_link,
    _sync_host_defaults,
    _get_network,
    _get_host,
    AUTO_LINK_SUPPRESSIONS_KEY,
)


class TestHelpersFinal:
    def test_node_ref_empty(self):
        assert _node_ref(None) == ""

    def test_node_ref_id_fallback(self):
        assert _node_ref({"id": "abc"}) == "abc"

    def test_node_ref_ip_priority(self):
        assert _node_ref({"host_id": "h1", "ip": "1.2.3.4", "id": "abc"}) == "h1"

    def test_edge_ref_empty_node(self):
        assert _edge_ref(None, {"host_id": "h1"}) == ""

    def test_edge_ref_sorted(self):
        r = _edge_ref({"host_id": "b"}, {"host_id": "a"})
        assert r == "a::b"

    def test_clear_suppressed_no_ref(self):
        meta = {}
        _clear_suppressed_auto_link(meta, "")
        assert AUTO_LINK_SUPPRESSIONS_KEY not in meta

    def test_clear_suppressed_removes_all(self):
        meta = {AUTO_LINK_SUPPRESSIONS_KEY: ["x::y"]}
        _clear_suppressed_auto_link(meta, "x::y")
        assert AUTO_LINK_SUPPRESSIONS_KEY not in meta

    def test_clear_suppressed_keeps_others(self):
        meta = {AUTO_LINK_SUPPRESSIONS_KEY: ["x::y", "a::b"]}
        _clear_suppressed_auto_link(meta, "x::y")
        assert meta[AUTO_LINK_SUPPRESSIONS_KEY] == ["a::b"]

    def test_add_suppressed_no_ref(self):
        meta = {}
        _add_suppressed_auto_link(meta, "")
        assert AUTO_LINK_SUPPRESSIONS_KEY not in meta

    def test_add_suppressed_sorted(self):
        meta = {}
        _add_suppressed_auto_link(meta, "b::a")
        _add_suppressed_auto_link(meta, "a::b")
        assert meta[AUTO_LINK_SUPPRESSIONS_KEY] == ["a::b", "b::a"]

    def test_sync_host_defaults_full(self):
        from unittest.mock import MagicMock
        host = MagicMock()
        host.hostname = "srv01"
        host.ip = "10.0.0.1"
        host.ips = ["10.0.0.1", "10.0.0.2"]
        host.ports = ["80/tcp"]
        host.status = "up"
        host.notes = "note"
        host.role = "server"
        host.is_attacker = False
        node = {}
        result = _sync_host_defaults(node, host)
        assert result["label"] == "srv01"
        assert result["ip"] == "10.0.0.1"
        assert result["status"] == "up"
        assert result["is_attacker"] is False

    def test_sync_host_defaults_no_override(self):
        from unittest.mock import MagicMock
        host = MagicMock()
        host.hostname = "srv01"
        host.ip = "10.0.0.1"
        host.ips = None
        host.ports = None
        host.status = "up"
        host.notes = ""
        host.role = ""
        host.is_attacker = None
        node = {"label": "custom", "ip": "1.1.1.1", "status": "down", "is_attacker": True, "notes": "n"}
        result = _sync_host_defaults(node, host)
        assert result["label"] == "custom"
        assert result["ip"] == "1.1.1.1"
        assert result["status"] == "down"
        assert result["is_attacker"] is True

    def test_sync_host_none(self):
        assert _sync_host_defaults({"a": 1}, None) == {"a": 1}

    def test_get_network_not_found(self):
        from unittest.mock import MagicMock
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        with pytest.raises(HTTPException) as exc_info:
            _get_network("p1", "n1", db)
        assert exc_info.value.status_code == 404

    def test_get_host_none_id(self):
        from unittest.mock import MagicMock
        db = MagicMock()
        assert _get_host("p1", None, db) is None

    def test_get_host_not_found(self):
        from unittest.mock import MagicMock
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        with pytest.raises(HTTPException) as exc_info:
            _get_host("p1", "h1", db)
        assert exc_info.value.status_code == 404

    def test_find_node_empty(self):
        with pytest.raises(HTTPException):
            _find_node([], "x")

    def test_find_edge_empty_list(self):
        with pytest.raises(HTTPException):
            _find_edge([], "x")
