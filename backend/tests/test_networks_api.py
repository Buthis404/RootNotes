"""Comprehensive API tests for the networks router."""

import pytest
from fastapi.testclient import TestClient

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _setup(module_client):
    module_client.post("/api/auth/setup", json={"username": "admin", "password": "TestPass1234!"})
    r = module_client.post("/api/auth/login", json={"username": "admin", "password": "TestPass1234!"})
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text}"
    r = module_client.post(
        "/api/projects",
        json={"name": "Networks Test Proj", "added": "2025-01-01T00:00:00Z", "status": "active"},
    )
    assert r.status_code in (201, 409), f"project: {r.status_code} {r.text}"
    if r.status_code == 201:
        _state["pid"] = r.json()["id"]
    else:
        ps = module_client.get("/api/projects").json()
        _state["pid"] = next(p["id"] for p in ps if p["name"] == "Networks Test Proj")
    yield


class TestNetworkCRUD:
    def test_create(self, module_client):
        r = module_client.post(
            "/api/networks",
            json={
                "pid": _state["pid"],
                "name": "Corp Network",
                "background": "#0d1117",
            },
        )
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["name"] == "Corp Network"
        assert data["background"] == "#0d1117"
        assert data["pid"] == _state["pid"]
        assert "id" in data
        assert data["nodes"] == []
        assert data["edges"] == []
        assert data["regions"] == []
        _state["netid"] = data["id"]

    def test_list(self, module_client):
        r = module_client.get("/api/networks", params={"pid": _state["pid"]})
        assert r.status_code == 200
        ids = [n["id"] for n in r.json()]
        assert _state["netid"] in ids

    def test_update_name(self, module_client):
        r = module_client.patch(
            f"/api/networks/{_state['netid']}",
            json={"name": "Renamed Network"},
        )
        assert r.status_code == 200
        assert r.json()["name"] == "Renamed Network"

    def test_update_background(self, module_client):
        r = module_client.patch(
            f"/api/networks/{_state['netid']}",
            json={"background": "#ffffff"},
        )
        assert r.status_code == 200
        assert r.json()["background"] == "#ffffff"

    def test_update_meta(self, module_client):
        r = module_client.patch(
            f"/api/networks/{_state['netid']}",
            json={"meta": {"zoom": 1.5, "pan_x": 100}},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["meta"]["zoom"] == 1.5

    def test_update_with_regions(self, module_client):
        r = module_client.patch(
            f"/api/networks/{_state['netid']}",
            json={
                "regions": [
                    {
                        "id": "reg1",
                        "x": 0,
                        "y": 0,
                        "w": 400,
                        "h": 300,
                        "label": "DMZ",
                    }
                ]
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert len(data["regions"]) == 1
        assert data["regions"][0]["label"] == "DMZ"

    def test_update_with_nodes(self, module_client):
        r = module_client.patch(
            f"/api/networks/{_state['netid']}",
            json={
                "nodes": [
                    {
                        "id": "node1",
                        "x": 100,
                        "y": 200,
                        "label": "Web Server",
                        "ip": "10.0.0.1",
                        "type": "server",
                    }
                ]
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert len(data["nodes"]) == 1
        assert data["nodes"][0]["label"] == "Web Server"

    def test_update_with_edges(self, module_client):
        r = module_client.patch(
            f"/api/networks/{_state['netid']}",
            json={
                "nodes": [
                    {
                        "id": "node_a",
                        "x": 100,
                        "y": 200,
                        "label": "A",
                        "ip": "10.0.0.1",
                        "type": "server",
                    },
                    {
                        "id": "node_b",
                        "x": 300,
                        "y": 400,
                        "label": "B",
                        "ip": "10.0.0.2",
                        "type": "server",
                    },
                ],
                "edges": [
                    {
                        "id": "edge1",
                        "from": "node_a",
                        "to": "node_b",
                        "style": "normal",
                        "label": "connects",
                    }
                ],
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert len(data["edges"]) == 1
        assert data["edges"][0]["label"] == "connects"

    def test_delete(self, module_client):
        r = module_client.delete(f"/api/networks/{_state['netid']}")
        assert r.status_code == 204
        r = module_client.get("/api/networks", params={"pid": _state["pid"]})
        ids = [n["id"] for n in r.json()]
        assert _state["netid"] not in ids


class TestNetworkEdgeCases:
    def test_update_nonexistent_returns_404(self, module_client):
        r = module_client.patch("/api/networks/nonexistent_net", json={"name": "x"})
        assert r.status_code == 404

    def test_delete_nonexistent_returns_404(self, module_client):
        r = module_client.delete("/api/networks/nonexistent_net")
        assert r.status_code == 404

    def test_create_second_network(self, module_client):
        r1 = module_client.post(
            "/api/networks",
            json={"pid": _state["pid"], "name": "Net Alpha"},
        )
        r2 = module_client.post(
            "/api/networks",
            json={"pid": _state["pid"], "name": "Net Beta"},
        )
        assert r1.status_code == 201
        assert r2.status_code == 201
        r = module_client.get("/api/networks", params={"pid": _state["pid"]})
        names = [n["name"] for n in r.json()]
        assert "Net Alpha" in names
        assert "Net Beta" in names

    def test_create_default_values(self, module_client):
        r = module_client.post(
            "/api/networks",
            json={"pid": _state["pid"], "name": "Defaults Net"},
        )
        assert r.status_code == 201
        data = r.json()
        assert data["background"] == "#07080b"
        assert data["nodes"] == []
        assert data["edges"] == []
        assert data["regions"] == []
