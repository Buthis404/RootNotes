"""Comprehensive tests for the knowledge-base API endpoints."""
import io
import json
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
    r = module_client.post("/api/projects", json={"name": "KBTest", "added": TS, "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]
    yield
    module_client.post("/api/auth/logout")


class TestCreateKBArticle:
    def test_create_project_article(self, module_client: TestClient):
        r = module_client.post("/api/kb", json={
            "pid": _state["pid"],
            "title": "Project KB Article",
            "content": "Some content",
            "category": "Reconnaissance",
            "tags": ["recon", "nmap"],
        })
        assert r.status_code == 201
        data = r.json()
        assert data["title"] == "Project KB Article"
        assert data["category"] == "Reconnaissance"
        assert "nmap" in data["tags"]
        _state["aid1"] = data["id"]

    def test_create_global_article(self, module_client: TestClient):
        r = module_client.post("/api/kb", json={
            "pid": None,
            "title": "Global KB Article",
            "content": "Global content",
            "category": "General",
            "tags": [],
        })
        assert r.status_code == 201
        data = r.json()
        assert data["pid"] is None
        assert data["title"] == "Global KB Article"
        _state["aid_global"] = data["id"]

    def test_create_minimal(self, module_client: TestClient):
        r = module_client.post("/api/kb", json={
            "pid": _state["pid"],
            "title": "Minimal Article",
        })
        assert r.status_code == 201
        _state["aid2"] = r.json()["id"]


class TestListKBArticles:
    def test_list_by_pid(self, module_client: TestClient):
        r = module_client.get("/api/kb", params={"pid": _state["pid"]})
        assert r.status_code == 200
        items = r.json()
        ids = [a["id"] for a in items]
        assert _state["aid1"] in ids
        assert _state["aid_global"] in ids

    def test_list_global_only(self, module_client: TestClient):
        r = module_client.get("/api/kb")
        assert r.status_code == 200
        for a in r.json():
            assert a["pid"] is None

    def test_list_filter_category(self, module_client: TestClient):
        r = module_client.get("/api/kb", params={"pid": _state["pid"], "category": "Reconnaissance"})
        assert r.status_code == 200
        for a in r.json():
            if a["pid"] == _state["pid"]:
                assert a["category"] == "Reconnaissance"

    def test_list_search_query(self, module_client: TestClient):
        r = module_client.get("/api/kb", params={"pid": _state["pid"], "q": "Project KB"})
        assert r.status_code == 200
        assert len(r.json()) >= 1


class TestGetKBArticle:
    def test_get_existing(self, module_client: TestClient):
        r = module_client.get(f"/api/kb/{_state['aid1']}")
        assert r.status_code == 200
        assert r.json()["title"] == "Project KB Article"

    def test_get_nonexistent(self, module_client: TestClient):
        r = module_client.get("/api/kb/kbnonexistent")
        assert r.status_code == 404


class TestUpdateKBArticle:
    def test_update_title(self, module_client: TestClient):
        r = module_client.patch(f"/api/kb/{_state['aid1']}", json={"title": "Updated Title"})
        assert r.status_code == 200
        assert r.json()["title"] == "Updated Title"

    def test_update_content_and_category(self, module_client: TestClient):
        r = module_client.patch(f"/api/kb/{_state['aid1']}", json={
            "content": "New content", "category": "Exploitation",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["content"] == "New content"
        assert data["category"] == "Exploitation"

    def test_update_nonexistent(self, module_client: TestClient):
        r = module_client.patch("/api/kb/kbnonexistent", json={"title": "x"})
        assert r.status_code == 404


class TestDeleteKBArticle:
    def test_delete(self, module_client: TestClient):
        r = module_client.post("/api/kb", json={"pid": _state["pid"], "title": "Delete Me"})
        aid = r.json()["id"]
        r = module_client.delete(f"/api/kb/{aid}")
        assert r.status_code == 204

    def test_delete_nonexistent(self, module_client: TestClient):
        r = module_client.delete("/api/kb/kbnonexistent")
        assert r.status_code == 404


class TestExportKB:
    def test_export_by_pid(self, module_client: TestClient):
        r = module_client.get("/api/kb/export", params={"pid": _state["pid"]})
        assert r.status_code == 200
        assert r.headers["content-type"] == "application/json"
        data = json.loads(r.text)
        assert data["format"] == "rootnotes-kb"
        assert len(data["articles"]) >= 1

    def test_export_global(self, module_client: TestClient):
        r = module_client.get("/api/kb/export")
        assert r.status_code == 200
        data = json.loads(r.text)
        assert isinstance(data["articles"], list)


class TestImportKB:
    def test_import_articles(self, module_client: TestClient):
        payload = json.dumps({
            "format": "rootnotes-kb",
            "version": "1",
            "articles": [
                {"title": "Imported Article", "content": "Imported", "category": "General", "tags": ["imported"]},
            ],
        }).encode()
        r = module_client.post(
            "/api/kb/import",
            params={"pid": _state["pid"]},
            files={"file": ("kb.json", io.BytesIO(payload), "application/json")},
        )
        assert r.status_code == 201
        data = r.json()
        assert data["created"] >= 1

    def test_import_skips_duplicates(self, module_client: TestClient):
        payload = json.dumps({
            "articles": [
                {"title": "Imported Article", "content": "Imported", "category": "General", "tags": ["imported"]},
            ],
        }).encode()
        r = module_client.post(
            "/api/kb/import",
            params={"pid": _state["pid"]},
            files={"file": ("kb.json", io.BytesIO(payload), "application/json")},
        )
        assert r.status_code == 201
        assert r.json()["skipped"] >= 1


class TestSeedMitre:
    def test_seed_mitre(self, module_client: TestClient):
        r = module_client.post("/api/kb/seed/mitre")
        assert r.status_code == 200
        data = r.json()
        assert "created" in data
        assert "total" in data

    def test_seed_mitre_idempotent(self, module_client: TestClient):
        r1 = module_client.post("/api/kb/seed/mitre")
        r2 = module_client.post("/api/kb/seed/mitre")
        assert r2.json()["created"] == 0
