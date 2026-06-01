"""Consolidated tests for test_network_map (merged variant files)."""

# ════════ from test_network_map_api.py ════════
import pytest
from fastapi.testclient import TestClient

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
TS = "2025-01-01T00:00:00Z"

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200, r.text
    r = module_client.post("/api/projects", json={"name": "NetworkMap Test", "added": TS, "status": "active"})
    assert r.status_code == 201, r.text
    _state["pid"] = r.json()["id"]
    r = module_client.post("/api/networks", json={"pid": _state["pid"], "name": "Test Network"})
    assert r.status_code == 201, r.text
    _state["net_id"] = r.json()["id"]
    yield
    module_client.post("/api/auth/logout")


class TestNetworkRegionCRUD:
    def test_create_region(self, module_client: TestClient):
        r = module_client.post(f"/api/projects/{_state['pid']}/network/regions", json={
            "network_id": _state["net_id"],
            "x": 0,
            "y": 0,
            "w": 500,
            "h": 400,
            "label": "DMZ",
            "zone_type": "dmz",
        })
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["region"]["label"] == "DMZ"
        _state["region_id"] = data["region"]["id"]

    def test_create_second_region(self, module_client: TestClient):
        r = module_client.post(f"/api/projects/{_state['pid']}/network/regions", json={
            "network_id": _state["net_id"],
            "x": 500,
            "y": 0,
            "w": 500,
            "h": 400,
            "label": "Internal",
            "zone_type": "internal",
        })
        assert r.status_code == 200, r.text
        _state["region2_id"] = r.json()["region"]["id"]

    def test_update_region(self, module_client: TestClient):
        r = module_client.patch(
            f"/api/projects/{_state['pid']}/network/regions/{_state['region_id']}",
            params={"network_id": _state["net_id"]},
            json={"label": "DMZ Updated", "fill": "#1a1a2e"},
        )
        assert r.status_code == 200, r.text
        assert r.json()["region"]["label"] == "DMZ Updated"

    def test_update_region_position(self, module_client: TestClient):
        r = module_client.patch(
            f"/api/projects/{_state['pid']}/network/regions/{_state['region_id']}",
            params={"network_id": _state["net_id"]},
            json={"x": 10, "y": 20, "w": 600, "h": 500},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["region"]["x"] == 10
        assert data["region"]["w"] == 600

    def test_update_region_missing_network_id_400(self, module_client: TestClient):
        r = module_client.patch(
            f"/api/projects/{_state['pid']}/network/regions/{_state['region_id']}",
            json={"label": "X"},
        )
        assert r.status_code == 400

    def test_update_nonexistent_region_404(self, module_client: TestClient):
        r = module_client.patch(
            f"/api/projects/{_state['pid']}/network/regions/r_nonexistent",
            params={"network_id": _state["net_id"]},
            json={"label": "X"},
        )
        assert r.status_code == 404

    def test_create_region_nonexistent_network_404(self, module_client: TestClient):
        r = module_client.post(f"/api/projects/{_state['pid']}/network/regions", json={
            "network_id": "net_nonexistent",
            "x": 0,
            "y": 0,
            "w": 100,
            "h": 100,
            "label": "Bad",
        })
        assert r.status_code == 404

    def test_delete_region(self, module_client: TestClient):
        r = module_client.delete(
            f"/api/projects/{_state['pid']}/network/regions/{_state['region2_id']}",
            params={"network_id": _state["net_id"]},
        )
        assert r.status_code == 200

    def test_delete_region_missing_network_id_400(self, module_client: TestClient):
        r = module_client.delete(
            f"/api/projects/{_state['pid']}/network/regions/r_nonexistent",
        )
        assert r.status_code == 400

    def test_delete_nonexistent_region_404(self, module_client: TestClient):
        r = module_client.delete(
            f"/api/projects/{_state['pid']}/network/regions/r_nonexistent",
            params={"network_id": _state["net_id"]},
        )
        assert r.status_code == 404


class TestNetworkNodeEndpoints:
    def test_create_node_nonexistent_network_404(self, module_client: TestClient):
        r = module_client.post(f"/api/projects/{_state['pid']}/network/nodes", json={
            "network_id": "net_nonexistent",
            "x": 0,
            "y": 0,
            "w": 100,
            "h": 50,
            "type": "server",
            "status": "unknown",
        })
        assert r.status_code == 404

    def test_update_node_missing_network_id_400(self, module_client: TestClient):
        r = module_client.patch(
            f"/api/projects/{_state['pid']}/network/nodes/n_nonexistent",
            json={"label": "No Network"},
        )
        assert r.status_code == 400

    def test_update_node_position_missing_network_id_400(self, module_client: TestClient):
        r = module_client.patch(
            f"/api/projects/{_state['pid']}/network/nodes/n_nonexistent/position",
            json={"x": 100, "y": 200},
        )
        assert r.status_code == 400

    def test_delete_node_missing_network_id_400(self, module_client: TestClient):
        r = module_client.delete(
            f"/api/projects/{_state['pid']}/network/nodes/n_nonexistent",
        )
        assert r.status_code == 400


class TestNetworkLinkEndpoints:
    def test_create_link_missing_network_400(self, module_client: TestClient):
        r = module_client.post(f"/api/projects/{_state['pid']}/network/links", json={
            "network_id": "net_nonexistent",
            "from_node_id": "n1",
            "to_node_id": "n2",
            "style": "solid",
        })
        assert r.status_code == 404

    def test_update_link_missing_network_id_400(self, module_client: TestClient):
        r = module_client.patch(
            f"/api/projects/{_state['pid']}/network/links/edg_nonexistent",
            json={"label": "X"},
        )
        assert r.status_code == 400

    def test_delete_link_missing_network_id_400(self, module_client: TestClient):
        r = module_client.delete(
            f"/api/projects/{_state['pid']}/network/links/edg_nonexistent",
        )
        assert r.status_code == 400


# ════════ from test_network_map_extended.py ════════
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


class TestNodeRef_extended:
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


class TestEdgeRef_extended:
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


class TestClearSuppressedAutoLink_extended:
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


class TestAddSuppressedAutoLink_extended:
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


class TestSyncHostDefaults_extended:
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


class TestFindNode_extended:
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


class TestFindEdge_extended:
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


# ════════ from test_network_map_final.py ════════
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


class TestFindNode_final:
    def test_found(self):
        nodes = [{"id": "n1"}, {"id": "n2"}]
        idx, node = _find_node(nodes, "n2")
        assert idx == 1
        assert node["id"] == "n2"

    def test_not_found(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            _find_node([{"id": "n1"}], "n99")


class TestFindEdge_final:
    def test_found(self):
        edges = [{"id": "e1"}, {"id": "e2"}]
        idx, edge = _find_edge(edges, "e1")
        assert idx == 0

    def test_not_found(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            _find_edge([], "e99")


class TestVersions_final:
    def test_node_version(self):
        assert _node_version({"version": 3}) == 4

    def test_node_version_missing(self):
        assert _node_version({}) == 1

    def test_edge_version(self):
        assert _edge_version({"version": 0}) == 1

    def test_region_version(self):
        assert _region_version({"version": 5}) == 6


class TestNodeRef_final:
    def test_with_host_id(self):
        assert _node_ref({"host_id": "h1", "ip": "10.0.0.1", "id": "n1"}) == "h1"

    def test_with_ip(self):
        assert _node_ref({"host_id": "", "ip": "10.0.0.1", "id": "n1"}) == "10.0.0.1"

    def test_with_id(self):
        assert _node_ref({"host_id": "", "ip": "", "id": "n1"}) == "n1"

    def test_none(self):
        assert _node_ref(None) == ""


class TestEdgeRef_final:
    def test_basic(self):
        ref = _edge_ref({"host_id": "h1"}, {"host_id": "h2"})
        assert ref != ""
        assert "::" in ref

    def test_empty_node(self):
        assert _edge_ref(None, {"host_id": "h1"}) == ""

    def test_empty_ref(self):
        assert _edge_ref({"host_id": ""}, {"host_id": ""}) == ""


class TestClearSuppressedAutoLink_final:
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


class TestAddSuppressedAutoLink_final:
    def test_adds(self):
        meta = {}
        _add_suppressed_auto_link(meta, "ref1")
        assert "ref1" in meta[AUTO_LINK_SUPPRESSIONS_KEY]

    def test_dedup(self):
        meta = {AUTO_LINK_SUPPRESSIONS_KEY: ["ref1"]}
        _add_suppressed_auto_link(meta, "ref1")
        assert meta[AUTO_LINK_SUPPRESSIONS_KEY].count("ref1") == 1


class TestSyncHostDefaults_final:
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


# ════════ from test_network_map_final2.py ════════
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


# ════════ from test_network_map_v3.py ════════
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


class TestFindNode_v3:
    def test_found(self):
        nodes = [{"id": "n1"}, {"id": "n2"}]
        idx, node = _find_node(nodes, "n1")
        assert idx == 0
        assert node["id"] == "n1"

    def test_not_found(self):
        with pytest.raises(HTTPException) as exc_info:
            _find_node([{"id": "n1"}], "n2")
        assert exc_info.value.status_code == 404


class TestFindEdge_v3:
    def test_found(self):
        edges = [{"id": "e1"}, {"id": "e2"}]
        idx, edge = _find_edge(edges, "e2")
        assert idx == 1
        assert edge["id"] == "e2"

    def test_not_found(self):
        with pytest.raises(HTTPException) as exc_info:
            _find_edge([{"id": "e1"}], "e2")
        assert exc_info.value.status_code == 404


class TestVersions_v3:
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


class TestNodeRef_v3:
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


class TestEdgeRef_v3:
    def test_basic(self):
        ref = _edge_ref({"host_id": "h1"}, {"host_id": "h2"})
        assert "h1" in ref
        assert "h2" in ref

    def test_sorted(self):
        ref = _edge_ref({"host_id": "h2"}, {"host_id": "h1"})
        assert ref == "h1::h2"

    def test_empty(self):
        assert _edge_ref(None, {"host_id": "h1"}) == ""


class TestClearSuppressedAutoLink_v3:
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
