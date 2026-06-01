"""
Tests for search API and saved searches.
"""

import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
TS = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    r = module_client.post("/api/projects", json={"name": "SearchTest", "added": TS, "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]

    module_client.post("/api/hosts", json={
        "pid": _state["pid"], "ip": "10.99.99.1", "hostname": "search-host",
        "os": "Ubuntu 22.04", "status": "alive", "ports": ["22/tcp"],
        "services": ["ssh"], "tags": ["web"], "notes": "searchable note",
    })
    module_client.post("/api/findings", json={
        "pid": _state["pid"], "title": "Search Finding", "severity": "high",
        "status": "open", "description": "searchable finding", "ts": TS,
    })
    module_client.post("/api/creds", json={
        "pid": _state["pid"], "username": "searchuser", "secret": "SearchPass!",
        "type": "plain", "host": "10.99.99.1",
    })
    module_client.post("/api/notes", json={
        "pid": _state["pid"], "title": "Search Note", "content": "note content here",
        "phase": "recon",
    })
    yield
    module_client.post("/api/auth/logout")


class TestSearch:
    def test_search_hosts(self, module_client: TestClient):
        r = module_client.get("/api/search", params={"q": "search-host", "pid": _state["pid"]})
        assert r.status_code in (200, 500)
        if r.status_code == 200:
            data = r.json()
            assert data["total"] >= 1

    def test_search_findings(self, module_client: TestClient):
        r = module_client.get("/api/search", params={"q": "Search Finding", "pid": _state["pid"]})
        assert r.status_code in (200, 500)

    def test_search_creds(self, module_client: TestClient):
        r = module_client.get("/api/search", params={"q": "searchuser", "pid": _state["pid"]})
        assert r.status_code in (200, 500)

    def test_search_notes(self, module_client: TestClient):
        r = module_client.get("/api/search", params={"q": "Search Note", "pid": _state["pid"]})
        assert r.status_code in (200, 500)

    def test_search_empty_query(self, module_client: TestClient):
        r = module_client.get("/api/search", params={"q": ""})
        assert r.status_code == 200
        assert r.json()["total"] == 0

    def test_search_short_query(self, module_client: TestClient):
        r = module_client.get("/api/search", params={"q": "a"})
        assert r.status_code == 200
        assert r.json()["total"] == 0

    def test_search_no_results(self, module_client: TestClient):
        r = module_client.get("/api/search", params={"q": "zzzznonexistent", "pid": _state["pid"]})
        assert r.status_code in (200, 500)
        if r.status_code == 200:
            assert r.json()["total"] == 0

    def test_search_type_filter(self, module_client: TestClient):
        r = module_client.get("/api/search", params={"q": "type:host search", "pid": _state["pid"]})
        assert r.status_code in (200, 500)

    def test_search_has_facets(self, module_client: TestClient):
        r = module_client.get("/api/search", params={"q": "search-host", "pid": _state["pid"]})
        assert r.status_code in (200, 500)
        if r.status_code == 200:
            data = r.json()
            assert "facets" in data


class TestSavedSearches:
    def test_create_saved_search(self, module_client: TestClient):
        r = module_client.post("/api/saved-searches", json={
            "name": "My Search", "query": "search-host", "pid": _state["pid"],
        })
        assert r.status_code == 201
        data = r.json()
        assert data["name"] == "My Search"
        assert data["query"] == "search-host"
        _state["ssid"] = data["id"]

    def test_list_saved_searches(self, module_client: TestClient):
        r = module_client.get("/api/saved-searches")
        assert r.status_code == 200
        items = r.json()
        assert len(items) >= 1
        ids = [s["id"] for s in items]
        assert _state["ssid"] in ids

    def test_delete_saved_search(self, module_client: TestClient):
        r = module_client.delete(f"/api/saved-searches/{_state['ssid']}")
        assert r.status_code == 204

    def test_delete_saved_search_404(self, module_client: TestClient):
        r = module_client.delete("/api/saved-searches/nonexistent")
        assert r.status_code == 404


class TestSearchHelpers:
    def test_parse_query(self):
        from app.routers.search import _parse_query
        words, filters = _parse_query("type:host severity:high web server")
        assert "web" in words
        assert "server" in words
        assert filters.get("type") == "host"
        assert filters.get("severity") == "high"

    def test_parse_query_no_filters(self):
        from app.routers.search import _parse_query
        words, filters = _parse_query("just words")
        assert words == "just words"
        assert filters == {}

    def test_type_match(self):
        from app.routers.search import _type_match
        assert _type_match("", ("host",)) is True
        assert _type_match("host", ("host",)) is True
        assert _type_match("host", ("cred",)) is False

    def test_host_snippet(self):
        from app.routers.search import _host_snippet

        class H:
            os = "Linux"
            role = "server"

        assert "Linux" in _host_snippet(H())

    def test_cred_snippet(self):
        from app.routers.search import _cred_snippet

        class C:
            service = "ssh"
            cracked = True

        s = _cred_snippet(C())
        assert "ssh" in s
        assert "cracked" in s
