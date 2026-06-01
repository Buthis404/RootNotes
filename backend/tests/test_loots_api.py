"""Comprehensive API tests for the loots router."""

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
        json={"name": "Loots Test Proj", "added": "2025-01-01T00:00:00Z", "status": "active"},
    )
    assert r.status_code in (201, 409), f"project: {r.status_code} {r.text}"
    if r.status_code == 201:
        _state["pid"] = r.json()["id"]
    else:
        ps = module_client.get("/api/projects").json()
        _state["pid"] = next(p["id"] for p in ps if p["name"] == "Loots Test Proj")
    yield


class TestLootCRUD:
    def test_create_hash_loot(self, module_client):
        r = module_client.post(
            "/api/loots",
            json={
                "pid": _state["pid"],
                "loot_type": "hash",
                "value": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
                "description": "NTLM hash",
                "artifact_type": "hash",
            },
        )
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["loot_type"] == "hash"
        assert data["artifact_type"] == "hash"
        assert "id" in data
        assert "ts" in data
        _state["lid"] = data["id"]

    def test_list(self, module_client):
        r = module_client.get("/api/loots", params={"pid": _state["pid"]})
        assert r.status_code == 200
        ids = [l["id"] for l in r.json()]
        assert _state["lid"] in ids

    def test_update_description(self, module_client):
        r = module_client.patch(
            f"/api/loots/{_state['lid']}",
            json={"description": "Updated NTLM hash description"},
        )
        assert r.status_code == 200
        assert r.json()["description"] == "Updated NTLM hash description"

    def test_update_tags(self, module_client):
        r = module_client.patch(
            f"/api/loots/{_state['lid']}",
            json={"tags": ["cracked", "admin"]},
        )
        assert r.status_code == 200
        assert r.json()["tags"] == ["cracked", "admin"]

    def test_delete(self, module_client):
        r = module_client.delete(f"/api/loots/{_state['lid']}")
        assert r.status_code == 204
        r = module_client.get("/api/loots", params={"pid": _state["pid"]})
        ids = [l["id"] for l in r.json()]
        assert _state["lid"] not in ids


class TestLootTypes:
    def test_create_file_loot(self, module_client):
        r = module_client.post(
            "/api/loots",
            json={
                "pid": _state["pid"],
                "loot_type": "file",
                "value": "secret.txt",
                "description": "Extracted secrets file",
                "artifact_type": "file",
            },
        )
        assert r.status_code == 201
        assert r.json()["loot_type"] == "file"

    def test_create_text_loot(self, module_client):
        r = module_client.post(
            "/api/loots",
            json={
                "pid": _state["pid"],
                "loot_type": "text",
                "value": "password=P@ssw0rd",
                "description": "Config file content",
                "artifact_type": "text",
            },
        )
        assert r.status_code == 201
        assert r.json()["loot_type"] == "text"
        _state["lid2"] = r.json()["id"]

    def test_create_credential_loot(self, module_client):
        r = module_client.post(
            "/api/loots",
            json={
                "pid": _state["pid"],
                "loot_type": "credential",
                "value": "admin:Password123",
                "description": "Creds from memory",
                "artifact_type": "credential",
            },
        )
        assert r.status_code == 201
        assert r.json()["loot_type"] == "credential"


class TestLootFilters:
    def test_filter_by_artifact_type(self, module_client):
        r = module_client.get(
            "/api/loots",
            params={"pid": _state["pid"], "artifact_type": "text"},
        )
        assert r.status_code == 200
        for item in r.json():
            assert item["artifact_type"] == "text"

    def test_filter_by_host_id(self, module_client):
        r = module_client.get(
            "/api/loots",
            params={"pid": _state["pid"], "host_id": "nonexistent"},
        )
        assert r.status_code == 200
        assert len(r.json()) == 0


class TestLootEdgeCases:
    def test_update_nonexistent_returns_404(self, module_client):
        r = module_client.patch("/api/loots/nonexistent_lt", json={"description": "x"})
        assert r.status_code == 404

    def test_delete_nonexistent_returns_404(self, module_client):
        r = module_client.delete("/api/loots/nonexistent_lt")
        assert r.status_code == 404

    def test_create_with_host_id(self, module_client):
        r_host = module_client.post(
            "/api/hosts",
            json={"pid": _state["pid"], "ip": "10.0.0.77"},
        )
        host_id = r_host.json()["id"]
        r = module_client.post(
            "/api/loots",
            json={
                "pid": _state["pid"],
                "host_id": host_id,
                "loot_type": "text",
                "value": "found on host",
                "artifact_type": "text",
            },
        )
        assert r.status_code == 201
        assert r.json()["host_id"] == host_id
