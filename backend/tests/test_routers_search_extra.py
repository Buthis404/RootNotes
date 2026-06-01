"""Extended tests for search — saved searches and helpers."""
import pytest
from fastapi.testclient import TestClient

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _setup(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    yield


class TestSavedSearches:
    def test_create_saved_search(self, module_client: TestClient):
        r = module_client.post("/api/saved-searches", json={
            "name": "Test Search", "query": "type:host 10.0.0",
        })
        assert r.status_code == 201
        data = r.json()
        assert data["name"] == "Test Search"
        _state["sid"] = data["id"]

    def test_list_saved_searches(self, module_client: TestClient):
        r = module_client.get("/api/saved-searches")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_delete_saved_search(self, module_client: TestClient):
        sid = _state.get("sid")
        if not sid:
            pytest.skip("no search id")
        r = module_client.delete(f"/api/saved-searches/{sid}")
        assert r.status_code == 204

    def test_delete_nonexistent(self, module_client: TestClient):
        r = module_client.delete("/api/saved-searches/nonexistent")
        assert r.status_code == 404


class TestSearchQuery:
    def test_short_query(self, module_client: TestClient):
        r = module_client.get("/api/search?q=a")
        assert r.status_code == 200
        assert r.json()["total"] == 0

    def test_empty_query(self, module_client: TestClient):
        r = module_client.get("/api/search?q=")
        assert r.status_code == 200
        assert r.json()["total"] == 0

    def test_search_with_type_filter(self, module_client: TestClient):
        r = module_client.get("/api/search?q=type:host+x")
        assert r.status_code == 200
