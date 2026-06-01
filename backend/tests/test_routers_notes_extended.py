"""Extended notes tests — attachments, versioning, confidential tags."""
import io
import pytest
from fastapi.testclient import TestClient

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    r = module_client.post("/api/projects", json={"name": "NotesExtTest", "added": "2025-01-01T00:00:00Z", "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]
    yield


class TestNoteCRUD:
    def test_create_note(self, module_client: TestClient):
        r = module_client.post(
            "/api/notes",
            json={"pid": _state["pid"], "title": "Test Note", "content": "hello", "phase": "recon", "ts": "2025-01-01T00:00:00Z"},
        )
        assert r.status_code == 201
        data = r.json()
        assert data["title"] == "Test Note"
        _state["nid"] = data["id"]

    def test_list_notes_by_pid(self, module_client: TestClient):
        r = module_client.get("/api/notes", params={"pid": _state["pid"]})
        assert r.status_code == 200
        assert len(r.json()) >= 1

    def test_update_note(self, module_client: TestClient):
        r = module_client.patch(f"/api/notes/{_state['nid']}", json={"title": "Updated Note"})
        assert r.status_code == 200
        assert r.json()["title"] == "Updated Note"

    def test_update_nonexistent(self, module_client: TestClient):
        r = module_client.patch("/api/notes/nonexistent", json={"title": "X"})
        assert r.status_code == 404


class TestNoteConfidential:
    def test_create_confidential_note(self, module_client: TestClient):
        r = module_client.post(
            "/api/notes",
            json={"pid": _state["pid"], "title": "Secret Note", "content": "secret data", "tags": ["confidential"], "ts": "2025-01-01T00:00:00Z"},
        )
        assert r.status_code == 201
        data = r.json()
        assert data["content"] == "secret data"


class TestNoteAttachments:
    def test_upload_attachment(self, module_client: TestClient):
        r = module_client.post(
            f"/api/notes/{_state['nid']}/attachments",
            files={"file": ("doc.txt", io.BytesIO(b"content"), "text/plain")},
        )
        assert r.status_code == 201
        data = r.json()
        assert data["filename"] == "doc.txt"
        _state["att_id"] = data["id"]

    def test_list_attachments(self, module_client: TestClient):
        r = module_client.get(f"/api/notes/{_state['nid']}/attachments")
        assert r.status_code == 200
        assert len(r.json()) >= 1

    def test_upload_nonexistent_note(self, module_client: TestClient):
        r = module_client.post(
            "/api/notes/nonexistent/attachments",
            files={"file": ("x.txt", io.BytesIO(b"x"), "text/plain")},
        )
        assert r.status_code == 404


class TestNoteDelete:
    def test_delete_note(self, module_client: TestClient):
        r = module_client.post(
            "/api/notes",
            json={"pid": _state["pid"], "title": "To Delete", "ts": "2025-01-01T00:00:00Z"},
        )
        nid = r.json()["id"]
        r = module_client.delete(f"/api/notes/{nid}")
        assert r.status_code == 204

    def test_delete_nonexistent(self, module_client: TestClient):
        r = module_client.delete("/api/notes/nonexistent")
        assert r.status_code == 404
