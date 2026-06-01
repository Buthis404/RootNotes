"""Cred-host-notes API integration tests — CRUD operations."""
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
    r = module_client.post("/api/projects", json={"name": "CredNotes Test", "added": TS, "status": "active"})
    assert r.status_code == 201, r.text
    _state["pid"] = r.json()["id"]
    r = module_client.post("/api/hosts", json={
        "pid": _state["pid"],
        "ip": "10.0.0.100",
        "hostname": "crednotes-host",
        "os": "Linux",
        "status": "unknown",
    })
    assert r.status_code == 201, r.text
    _state["host_id"] = r.json()["id"]
    r = module_client.post("/api/creds", json={
        "pid": _state["pid"],
        "username": "testuser",
        "secret": "TestPass123!",
        "type": "plain",
        "host": "10.0.0.100",
    })
    assert r.status_code == 201, r.text
    _state["cred_id"] = r.json()["id"]
    yield
    module_client.post("/api/auth/logout")


class TestCreateCredHostNote:
    def test_create_note(self, module_client: TestClient):
        r = module_client.post("/api/cred-host-notes", json={
            "cred_id": _state["cred_id"],
            "host_id": _state["host_id"],
            "pid": _state["pid"],
            "notes": "Valid on this host",
            "access": ["rdp", "smb"],
        })
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["notes"] == "Valid on this host"
        assert "rdp" in data["access"]
        _state["note_id"] = data["id"]

    def test_create_note_upserts_existing(self, module_client: TestClient):
        r = module_client.post("/api/cred-host-notes", json={
            "cred_id": _state["cred_id"],
            "host_id": _state["host_id"],
            "pid": _state["pid"],
            "notes": "Updated notes",
            "access": ["ssh"],
        })
        assert r.status_code == 201
        assert r.json()["notes"] == "Updated notes"


class TestListCredHostNotes:
    def test_list_notes_by_pid(self, module_client: TestClient):
        r = module_client.get("/api/cred-host-notes", params={"pid": _state["pid"]})
        assert r.status_code == 200
        data = r.json()
        assert len(data) > 0

    def test_list_notes_by_cred_id(self, module_client: TestClient):
        r = module_client.get("/api/cred-host-notes", params={"cred_id": _state["cred_id"]})
        assert r.status_code == 200
        data = r.json()
        assert any(n["cred_id"] == _state["cred_id"] for n in data)

    def test_list_notes_by_host_id(self, module_client: TestClient):
        r = module_client.get("/api/cred-host-notes", params={"host_id": _state["host_id"]})
        assert r.status_code == 200
        data = r.json()
        assert any(n["host_id"] == _state["host_id"] for n in data)


class TestUpdateCredHostNote:
    def test_update_note(self, module_client: TestClient):
        r = module_client.patch(f"/api/cred-host-notes/{_state['note_id']}", json={
            "notes": "Pwned via SMB",
            "access": ["smb", "admin"],
        })
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["notes"] == "Pwned via SMB"
        assert "admin" in data["access"]

    def test_update_nonexistent_note_404(self, module_client: TestClient):
        r = module_client.patch("/api/cred-host-notes/chn_nonexistent", json={"notes": "x"})
        assert r.status_code == 404


class TestDeleteCredHostNote:
    def test_delete_note(self, module_client: TestClient):
        r = module_client.delete(f"/api/cred-host-notes/{_state['note_id']}")
        assert r.status_code == 204

    def test_deleted_note_not_in_list(self, module_client: TestClient):
        r = module_client.get("/api/cred-host-notes", params={"pid": _state["pid"]})
        ids = [n["id"] for n in r.json()]
        assert _state["note_id"] not in ids

    def test_delete_nonexistent_note_404(self, module_client: TestClient):
        r = module_client.delete("/api/cred-host-notes/chn_nonexistent")
        assert r.status_code == 404
