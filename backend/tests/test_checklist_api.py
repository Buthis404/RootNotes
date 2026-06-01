"""Comprehensive API tests for the checklist router."""

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
        json={"name": "Checklist Test Proj", "added": "2025-01-01T00:00:00Z", "status": "active"},
    )
    assert r.status_code in (201, 409), f"project: {r.status_code} {r.text}"
    if r.status_code == 201:
        _state["pid"] = r.json()["id"]
    else:
        ps = module_client.get("/api/projects").json()
        _state["pid"] = next(p["id"] for p in ps if p["name"] == "Checklist Test Proj")
    yield


class TestChecklistCRUD:
    def test_bulk_create(self, module_client):
        r = module_client.post(
            "/api/checklist",
            json=[
                {
                    "pid": _state["pid"],
                    "phase": "recon",
                    "text": "Run Nmap scan",
                    "done": False,
                    "order_idx": 0,
                },
                {
                    "pid": _state["pid"],
                    "phase": "recon",
                    "text": "Enumerate SMB shares",
                    "done": False,
                    "order_idx": 1,
                },
                {
                    "pid": _state["pid"],
                    "phase": "exploitation",
                    "text": "Exploit web vulnerability",
                    "done": False,
                    "order_idx": 2,
                },
            ],
        )
        assert r.status_code == 201, r.text
        data = r.json()
        assert len(data) == 3
        assert data[0]["text"] == "Run Nmap scan"
        assert data[0]["phase"] == "recon"
        _state["cl_ids"] = [item["id"] for item in data]

    def test_list(self, module_client):
        r = module_client.get("/api/checklist", params={"pid": _state["pid"]})
        assert r.status_code == 200
        ids = [item["id"] for item in r.json()]
        for cid in _state["cl_ids"]:
            assert cid in ids

    def test_list_filter_by_phase(self, module_client):
        r = module_client.get(
            "/api/checklist",
            params={"pid": _state["pid"], "phase": "recon"},
        )
        assert r.status_code == 200
        for item in r.json():
            assert item["phase"] == "recon"

    def test_list_ordered_by_order_idx(self, module_client):
        r = module_client.get("/api/checklist", params={"pid": _state["pid"]})
        items = r.json()
        order_indices = [item["order_idx"] for item in items]
        assert order_indices == sorted(order_indices)

    def test_update_check_done(self, module_client):
        r = module_client.patch(
            f"/api/checklist/{_state['cl_ids'][0]}",
            json={"done": True},
        )
        assert r.status_code == 200
        assert r.json()["done"] is True

    def test_update_uncheck(self, module_client):
        r = module_client.patch(
            f"/api/checklist/{_state['cl_ids'][0]}",
            json={"done": False},
        )
        assert r.status_code == 200
        assert r.json()["done"] is False

    def test_update_text(self, module_client):
        r = module_client.patch(
            f"/api/checklist/{_state['cl_ids'][1]}",
            json={"text": "Enumerate all SMB shares"},
        )
        assert r.status_code == 200
        assert r.json()["text"] == "Enumerate all SMB shares"

    def test_update_order_idx(self, module_client):
        r = module_client.patch(
            f"/api/checklist/{_state['cl_ids'][1]}",
            json={"order_idx": 10},
        )
        assert r.status_code == 200
        assert r.json()["order_idx"] == 10

    def test_delete(self, module_client):
        for cid in _state["cl_ids"]:
            r = module_client.delete(f"/api/checklist/{cid}")
            assert r.status_code == 204
        r = module_client.get("/api/checklist", params={"pid": _state["pid"]})
        ids = [item["id"] for item in r.json()]
        for cid in _state["cl_ids"]:
            assert cid not in ids


class TestChecklistEdgeCases:
    def test_update_nonexistent_returns_404(self, module_client):
        r = module_client.patch("/api/checklist/nonexistent_cl", json={"done": True})
        assert r.status_code == 404

    def test_delete_nonexistent_returns_404(self, module_client):
        r = module_client.delete("/api/checklist/nonexistent_cl")
        assert r.status_code == 404

    def test_bulk_create_empty_list(self, module_client):
        r = module_client.post("/api/checklist", json=[])
        assert r.status_code == 201

    def test_bulk_create_single_item(self, module_client):
        r = module_client.post(
            "/api/checklist",
            json=[
                {
                    "pid": _state["pid"],
                    "phase": "post_exploitation",
                    "text": "Dump hashes",
                    "done": False,
                    "order_idx": 0,
                }
            ],
        )
        assert r.status_code == 201
        assert len(r.json()) == 1
        _state["single_cl_id"] = r.json()[0]["id"]

    def test_list_returns_correct_count(self, module_client):
        r = module_client.get("/api/checklist", params={"pid": _state["pid"]})
        assert r.status_code == 200
        assert len(r.json()) >= 1

    def test_pid_is_required_for_list(self, module_client):
        r = module_client.get("/api/checklist")
        assert r.status_code == 422
