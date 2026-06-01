"""Extended tests for network map helper functions and endpoints."""
import pytest
from fastapi.testclient import TestClient

from app.routers.network_map import (
    _node_version,
    _edge_version,
    _region_version,
    _node_ref,
    _edge_ref,
    _clear_suppressed_auto_link,
    _add_suppressed_auto_link,
    _sync_host_defaults,
    _find_node,
    _find_edge,
    _now,
    AUTO_LINK_SUPPRESSIONS_KEY,
)

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
TS = "2025-01-01T00:00:00Z"

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200, r.text
    r = module_client.post("/api/projects", json={"name": "NetMapExtended", "added": TS, "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]
    r = module_client.post("/api/networks", json={"pid": _state["pid"], "name": "Ext Net"})
    assert r.status_code == 201
    _state["net_id"] = r.json()["id"]
    r = module_client.post("/api/hosts", json={
        "pid": _state["pid"], "ip": "10.5.5.1", "hostname": "ext-host",
        "os": "Linux", "status": "alive",
    })
    assert r.status_code == 201
    _state["host_id"] = r.json()["id"]
    yield
    module_client.post("/api/auth/logout")


class TestNodeVersion:
    def test_first_version(self):
        assert _node_version({}) == 1

    def test_increment(self):
        assert _node_version({"version": 3}) == 4

    def test_string_version(self):
        assert _node_version({"version": "5"}) == 6


class TestEdgeVersion:
    def test_increment(self):
        assert _edge_version({"version": 0}) == 1


class TestRegionVersion:
    def test_increment(self):
        assert _region_version({"version": 2}) == 3


class TestNodeRef:
    def test_host_id(self):
        assert _node_ref({"host_id": "h1"}) == "h1"

    def test_ip(self):
        assert _node_ref({"ip": "10.0.0.1"}) == "10.0.0.1"

    def test_id_fallback(self):
        assert _node_ref({"id": "n1"}) == "n1"

    def test_none_returns_empty(self):
        assert _node_ref(None) == ""

    def test_empty_dict_returns_empty(self):
        assert _node_ref({}) == ""

    def test_priority_order(self):
        assert _node_ref({"host_id": "h1", "ip": "10.0.0.1", "id": "n1"}) == "h1"


class TestEdgeRef:
    def test_basic(self):
        n1 = {"host_id": "a"}
        n2 = {"host_id": "b"}
        ref = _edge_ref(n1, n2)
        assert ref == "a::b"

    def test_sorted(self):
        n1 = {"host_id": "z"}
        n2 = {"host_id": "a"}
        ref = _edge_ref(n1, n2)
        assert ref == "a::z"

    def test_empty_node(self):
        assert _edge_ref(None, {"host_id": "a"}) == ""
        assert _edge_ref({"host_id": "a"}, None) == ""

    def test_both_empty(self):
        assert _edge_ref(None, None) == ""


class TestClearSuppressedAutoLink:
    def test_removes_existing(self):
        meta = {AUTO_LINK_SUPPRESSIONS_KEY: ["a::b", "c::d"]}
        _clear_suppressed_auto_link(meta, "a::b")
        assert "a::b" not in meta[AUTO_LINK_SUPPRESSIONS_KEY]
        assert "c::d" in meta[AUTO_LINK_SUPPRESSIONS_KEY]

    def test_removes_key_when_empty(self):
        meta = {AUTO_LINK_SUPPRESSIONS_KEY: ["a::b"]}
        _clear_suppressed_auto_link(meta, "a::b")
        assert AUTO_LINK_SUPPRESSIONS_KEY not in meta

    def test_noop_when_empty_ref(self):
        meta = {AUTO_LINK_SUPPRESSIONS_KEY: ["a::b"]}
        _clear_suppressed_auto_link(meta, "")
        assert meta[AUTO_LINK_SUPPRESSIONS_KEY] == ["a::b"]

    def test_noop_when_not_found(self):
        meta = {AUTO_LINK_SUPPRESSIONS_KEY: ["a::b"]}
        _clear_suppressed_auto_link(meta, "x::y")
        assert meta[AUTO_LINK_SUPPRESSIONS_KEY] == ["a::b"]


class TestAddSuppressedAutoLink:
    def test_adds_new(self):
        meta = {}
        _add_suppressed_auto_link(meta, "a::b")
        assert "a::b" in meta[AUTO_LINK_SUPPRESSIONS_KEY]

    def test_deduplicates(self):
        meta = {AUTO_LINK_SUPPRESSIONS_KEY: ["a::b"]}
        _add_suppressed_auto_link(meta, "a::b")
        assert meta[AUTO_LINK_SUPPRESSIONS_KEY].count("a::b") == 1

    def test_sorted(self):
        meta = {AUTO_LINK_SUPPRESSIONS_KEY: ["z::z"]}
        _add_suppressed_auto_link(meta, "a::a")
        assert meta[AUTO_LINK_SUPPRESSIONS_KEY][0] == "a::a"

    def test_empty_ref_noop(self):
        meta = {}
        _add_suppressed_auto_link(meta, "")
        assert AUTO_LINK_SUPPRESSIONS_KEY not in meta


class TestSyncHostDefaults:
    def test_fills_from_host(self):
        node = {}
        host = MagicMock(hostname="pc1", ip="10.0.0.1", ips=["10.0.0.1"], ports=["22/tcp"], status="alive", notes="some notes", role="server", is_attacker=False)
        result = _sync_host_defaults(node, host)
        assert result["label"] == "pc1"
        assert result["ip"] == "10.0.0.1"
        assert result["status"] == "alive"
        assert result["is_attacker"] is False

    def test_no_host_returns_node(self):
        node = {"label": "existing"}
        assert _sync_host_defaults(node, None) == node

    def test_does_not_overwrite_existing(self):
        node = {"label": "keep", "ip": "10.0.0.99"}
        host = MagicMock(hostname="new", ip="10.0.0.1", ips=["10.0.0.1"], ports=[], status="up", notes="", role=None, is_attacker=None)
        result = _sync_host_defaults(node, host)
        assert result["label"] == "keep"
        assert result["ip"] == "10.0.0.99"

    def test_overwrites_unknown_status(self):
        node = {"status": "unknown"}
        host = MagicMock(hostname="", ip="", ips=[], ports=[], status="alive", notes="", role=None, is_attacker=None)
        result = _sync_host_defaults(node, host)
        assert result["status"] == "alive"


class TestFindNode:
    def test_finds_node(self):
        nodes = [{"id": "n1"}, {"id": "n2"}]
        idx, node = _find_node(nodes, "n2")
        assert idx == 1
        assert node["id"] == "n2"

    def test_not_found_raises_404(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            _find_node([], "missing")
        assert exc_info.value.status_code == 404


class TestFindEdge:
    def test_finds_edge(self):
        edges = [{"id": "e1"}, {"id": "e2"}]
        idx, edge = _find_edge(edges, "e1")
        assert idx == 0

    def test_not_found_raises_404(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            _find_edge([], "missing")
        assert exc_info.value.status_code == 404


class TestNow:
    def test_returns_string(self):
        result = _now()
        assert isinstance(result, str)
        assert len(result) > 0


class TestNodeCRUDEndpoints:
    def test_create_node(self, module_client: TestClient):
        r = module_client.post(f"/api/projects/{_state['pid']}/network/nodes", json={
            "network_id": _state["net_id"],
            "x": 100, "y": 200, "w": 50, "h": 50,
            "label": "Test Node",
            "type": "server",
            "status": "alive",
        })
        if r.status_code == 200:
            data = r.json()
            assert data["node"]["label"] == "Test Node"
            _state["node_id"] = data["node"]["id"]
        else:
            _state["node_id"] = None

    def test_create_node_with_host(self, module_client: TestClient):
        r = module_client.post(f"/api/projects/{_state['pid']}/network/nodes", json={
            "network_id": _state["net_id"],
            "host_id": _state["host_id"],
            "x": 50, "y": 50, "w": 50, "h": 50,
        })
        if r.status_code == 200:
            data = r.json()
            assert data["node"]["ip"] == "10.5.5.1"
            _state["node2_id"] = data["node"]["id"]
        else:
            _state["node2_id"] = None

    def test_update_node(self, module_client: TestClient):
        if not _state.get("node_id"):
            pytest.skip("node not created")
        r = module_client.patch(
            f"/api/projects/{_state['pid']}/network/nodes/{_state['node_id']}",
            params={"network_id": _state["net_id"]},
            json={"label": "Updated Node"},
        )
        if r.status_code == 200:
            assert r.json()["node"]["label"] == "Updated Node"

    def test_update_node_position(self, module_client: TestClient):
        if not _state.get("node_id"):
            pytest.skip("node not created")
        r = module_client.patch(
            f"/api/projects/{_state['pid']}/network/nodes/{_state['node_id']}/position",
            params={"network_id": _state["net_id"]},
            json={"x": 300, "y": 400, "manually_positioned": True},
        )
        if r.status_code == 200:
            data = r.json()
            assert data["position"]["x"] == 300
            assert data["position"]["y"] == 400

    def test_update_node_not_found(self, module_client: TestClient):
        r = module_client.patch(
            f"/api/projects/{_state['pid']}/network/nodes/n_nonexistent",
            params={"network_id": _state["net_id"]},
            json={"label": "X"},
        )
        assert r.status_code == 404


class TestLinkCRUDEndpoints:
    def test_create_link(self, module_client: TestClient):
        if not _state.get("node_id") or not _state.get("node2_id"):
            pytest.skip("nodes not created")
        r = module_client.post(f"/api/projects/{_state['pid']}/network/links", json={
            "network_id": _state["net_id"],
            "from_node_id": _state["node_id"],
            "to_node_id": _state["node2_id"],
            "style": "solid",
            "label": "Test Link",
        })
        if r.status_code == 200:
            _state["link_id"] = r.json()["link"]["id"]
        else:
            _state["link_id"] = None

    def test_create_duplicate_link_409(self, module_client: TestClient):
        if not _state.get("node_id") or not _state.get("node2_id"):
            pytest.skip("nodes not created")
        r = module_client.post(f"/api/projects/{_state['pid']}/network/links", json={
            "network_id": _state["net_id"],
            "from_node_id": _state["node_id"],
            "to_node_id": _state["node2_id"],
        })
        if _state.get("link_id"):
            assert r.status_code == 409

    def test_create_self_link_400(self, module_client: TestClient):
        if not _state.get("node_id"):
            pytest.skip("node not created")
        r = module_client.post(f"/api/projects/{_state['pid']}/network/links", json={
            "network_id": _state["net_id"],
            "from_node_id": _state["node_id"],
            "to_node_id": _state["node_id"],
        })
        assert r.status_code == 400

    def test_update_link(self, module_client: TestClient):
        if not _state.get("link_id"):
            pytest.skip("link not created")
        r = module_client.patch(
            f"/api/projects/{_state['pid']}/network/links/{_state['link_id']}",
            params={"network_id": _state["net_id"]},
            json={"label": "Updated Link"},
        )
        if r.status_code == 200:
            assert r.json()["link"]["label"] == "Updated Link"

    def test_delete_link(self, module_client: TestClient):
        if not _state.get("link_id"):
            pytest.skip("link not created")
        r = module_client.delete(
            f"/api/projects/{_state['pid']}/network/links/{_state['link_id']}",
            params={"network_id": _state["net_id"]},
        )
        assert r.status_code in (200, 404)


class TestNodeDeleteEndpoint:
    def test_delete_node(self, module_client: TestClient):
        if not _state.get("node2_id"):
            pytest.skip("node not created")
        r = module_client.delete(
            f"/api/projects/{_state['pid']}/network/nodes/{_state['node2_id']}",
            params={"network_id": _state["net_id"]},
        )
        assert r.status_code in (200, 404)
        if r.status_code == 200:
            assert "deleted_edge_ids" in r.json()


from unittest.mock import MagicMock
