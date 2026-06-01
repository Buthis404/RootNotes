"""Extended tests for network_map — region and suppression helpers."""
import pytest
from fastapi.testclient import TestClient

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _setup(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200, f"login: {r.status_code} {r.text}"
    r = module_client.post("/api/projects", json={"name": "NETMAP_EXT_PROJECT", "added": "2025-01-01T00:00:00Z", "status": "active"})
    if r.status_code == 201:
        _state["pid"] = r.json()["id"]
    else:
        ps = module_client.get("/api/projects").json()
        _state["pid"] = next(p["id"] for p in ps if p["name"] == "NETMAP_EXT_PROJECT")
    pid = _state["pid"]
    nets = module_client.get(f"/api/networks?pid={pid}").json()
    if nets:
        _state["net_id"] = nets[0]["id"]
    else:
        r = module_client.post("/api/networks", json={"pid": pid, "name": "Map", "background": "#000"})
        _state["net_id"] = r.json()["id"]
    yield


class TestNetworkMapRegions:
    def test_create_region(self, module_client: TestClient):
        pid, nid = _state["pid"], _state["net_id"]
        r = module_client.post(f"/api/projects/{pid}/network/regions?network_id={nid}", json={
            "network_id": nid, "x": 10, "y": 10, "w": 200, "h": 100,
            "label": "DMZ", "note": "Demilitarized zone", "fill": "#333",
            "stroke": "#fff", "zone_type": "dmz",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["region"]["label"] == "DMZ"
        _state["region_id"] = data["region"]["id"]

    def test_update_region(self, module_client: TestClient):
        pid, nid = _state["pid"], _state["net_id"]
        rid = _state.get("region_id")
        if not rid:
            pytest.skip("no region")
        r = module_client.patch(
            f"/api/projects/{pid}/network/regions/{rid}?network_id={nid}",
            json={"label": "DMZ Updated"},
        )
        assert r.status_code == 200
        assert r.json()["region"]["label"] == "DMZ Updated"

    def test_delete_region(self, module_client: TestClient):
        pid, nid = _state["pid"], _state["net_id"]
        rid = _state.get("region_id")
        if not rid:
            pytest.skip("no region")
        r = module_client.delete(f"/api/projects/{pid}/network/regions/{rid}?network_id={nid}")
        assert r.status_code == 200


class TestNetworkMapNodes:
    def test_create_node_missing_network(self, module_client: TestClient):
        pid = _state["pid"]
        r = module_client.post(f"/api/projects/{pid}/network/nodes", json={
            "network_id": "nonexistent", "x": 0, "y": 0, "w": 100, "h": 100,
        })
        assert r.status_code == 404


class TestNetworkMapLinks:
    def test_create_link_missing_network(self, module_client: TestClient):
        pid = _state["pid"]
        r = module_client.post(f"/api/projects/{pid}/network/links", json={
            "network_id": "nonexistent",
            "from_node_id": "a", "to_node_id": "b",
        })
        assert r.status_code == 404
