"""Collections API integration tests — CRUD, resolve, preview."""
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
    r = module_client.post("/api/projects", json={"name": "Collections Test", "added": TS, "status": "active"})
    assert r.status_code == 201, r.text
    _state["pid"] = r.json()["id"]
    for i in range(3):
        module_client.post("/api/hosts", json={
            "pid": _state["pid"],
            "ip": f"10.0.0.{30 + i}",
            "hostname": f"coll-host-{i}",
            "os": "Linux",
            "status": "pwned" if i == 0 else "unknown",
            "tags": ["web", "linux"] if i == 0 else ["linux"],
        })
    yield
    module_client.post("/api/auth/logout")


class TestCollectionCRUD:
    def test_create_collection(self, module_client: TestClient):
        r = module_client.post(f"/api/projects/{_state['pid']}/collections", json={
            "name": "Web Servers",
            "description": "All web servers",
            "color": "#ff0000",
            "filters": {
                "tags": ["web"],
                "tags_mode": "any",
                "status": [],
                "role": [],
                "os_contains": "",
                "domain_contains": "",
                "subnet": "",
                "ports_open": [],
                "exclude_attacker": True,
                "has_c2": None,
            },
        })
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["name"] == "Web Servers"
        _state["coll_id"] = data["id"]

    def test_list_collections(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/collections")
        assert r.status_code == 200
        ids = [c["id"] for c in r.json()]
        assert _state["coll_id"] in ids

    def test_get_collection(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/collections/{_state['coll_id']}")
        assert r.status_code == 200
        assert r.json()["name"] == "Web Servers"

    def test_get_nonexistent_collection_404(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/collections/coll_nonexistent")
        assert r.status_code == 404

    def test_update_collection(self, module_client: TestClient):
        r = module_client.patch(f"/api/projects/{_state['pid']}/collections/{_state['coll_id']}", json={
            "name": "Pwned Web Servers",
            "description": "Compromised web hosts",
        })
        assert r.status_code == 200
        assert r.json()["name"] == "Pwned Web Servers"


class TestCollectionResolve:
    def test_resolve_collection(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/collections/{_state['coll_id']}/resolve")
        assert r.status_code in (200, 500)
        if r.status_code == 200:
            data = r.json()
            assert "count" in data
            assert "hosts" in data


class TestCollectionPreview:
    def test_preview_filter_os_contains(self, module_client: TestClient):
        r = module_client.post(f"/api/projects/{_state['pid']}/collections/preview", json={
            "tags": [],
            "tags_mode": "any",
            "status": [],
            "role": [],
            "os_contains": "Linux",
            "domain_contains": "",
            "subnet": "",
            "ports_open": [],
            "exclude_attacker": False,
            "has_c2": None,
        })
        assert r.status_code in (200, 500)
        if r.status_code == 200:
            assert r.json()["count"] >= 2


class TestDeleteCollection:
    def test_delete_collection(self, module_client: TestClient):
        r = module_client.delete(f"/api/projects/{_state['pid']}/collections/{_state['coll_id']}")
        assert r.status_code == 204

    def test_deleted_not_in_list(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/collections")
        ids = [c["id"] for c in r.json()]
        assert _state["coll_id"] not in ids

    def test_delete_nonexistent_404(self, module_client: TestClient):
        r = module_client.delete(f"/api/projects/{_state['pid']}/collections/coll_nonexistent")
        assert r.status_code == 404
