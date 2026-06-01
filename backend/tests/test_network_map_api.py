"""Network map API integration tests — regions CRUD, nodes/links error handling."""
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
