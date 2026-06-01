"""Consolidated tests for test_playbooks_routes (merged variant files)."""

# ════════ from test_playbooks_routes_extended.py ════════
import io
import json
import pytest
from fastapi.testclient import TestClient

from app.plugins.loader import _register_builtin_modules

_register_builtin_modules()

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _setup(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    yield


class TestPlaybookTemplates:
    def test_list_step_templates(self, module_client: TestClient):
        r = module_client.get("/api/playbooks/step-templates")
        assert r.status_code == 200
        assert "templates" in r.json()

    def test_validate_playbook(self, module_client: TestClient):
        r = module_client.post("/api/playbooks/validate", json={
            "title": "Test PB", "description": "desc",
            "steps": [{"title": "step1", "connector_key": "nmap", "operation": "scan"}],
        })
        assert r.status_code == 200


class TestPlaybookCRUD:
    def test_create_custom(self, module_client: TestClient):
        r = module_client.post("/api/playbooks/custom", json={
            "title": "EXT Test PB", "description": "test",
            "steps": [{"title": "s1", "connector_key": "nmap", "operation": "scan"}],
        })
        assert r.status_code == 201
        _state["pb_id"] = r.json()["id"]

    def test_update_custom(self, module_client: TestClient):
        pb_id = _state.get("pb_id")
        if not pb_id:
            pytest.skip("no playbook")
        r = module_client.patch(f"/api/playbooks/custom/{pb_id}", json={
            "title": "EXT Test Updated", "description": "updated",
            "steps": [{"title": "s1", "connector_key": "nmap", "operation": "scan"}],
        })
        assert r.status_code == 200

    def test_update_nonexistent(self, module_client: TestClient):
        r = module_client.patch("/api/playbooks/custom/nonexistent", json={
            "title": "X", "steps": [],
        })
        assert r.status_code == 404

    def test_delete_custom(self, module_client: TestClient):
        pb_id = _state.get("pb_id")
        if not pb_id:
            pytest.skip("no playbook")
        r = module_client.delete(f"/api/playbooks/custom/{pb_id}")
        assert r.status_code == 204

    def test_delete_nonexistent(self, module_client: TestClient):
        r = module_client.delete("/api/playbooks/custom/nonexistent_pb")
        assert r.status_code == 404


class TestPlaybookImportExport:
    def test_export_empty(self, module_client: TestClient):
        r = module_client.get("/api/playbooks/custom/export")
        assert r.status_code == 200

    def test_import_playbooks(self, module_client: TestClient):
        import uuid
        title = f"Imported PB {uuid.uuid4().hex[:8]}"
        data = json.dumps({
            "format": "rootnotes-playbooks",
            "version": "1",
            "playbooks": [{"title": title, "description": "test", "steps": []}],
        }).encode()
        r = module_client.post(
            "/api/playbooks/custom/import",
            files={"file": ("playbooks.json", io.BytesIO(data), "application/json")},
        )
        assert r.status_code == 201
        assert r.json()["created"] >= 1


class TestOperationPacks:
    def test_list_packs(self, module_client: TestClient):
        r = module_client.get("/api/playbooks/packs")
        assert r.status_code == 200
        assert "packs" in r.json()

    def test_create_pack(self, module_client: TestClient):
        r = module_client.post("/api/playbooks/packs", json={
            "name": "Test Pack EXT", "description": "test",
            "steps": [], "tags": ["test"],
        })
        assert r.status_code == 201
        _state["pack_id"] = r.json()["id"]

    def test_delete_pack(self, module_client: TestClient):
        pack_id = _state.get("pack_id")
        if not pack_id:
            pytest.skip("no pack")
        r = module_client.delete(f"/api/playbooks/packs/{pack_id}")
        assert r.status_code == 204

    def test_delete_nonexistent_pack(self, module_client: TestClient):
        r = module_client.delete("/api/playbooks/packs/nonexistent_pack")
        assert r.status_code == 404


# ════════ from test_playbooks_routes_final.py ════════
import pytest
from unittest.mock import MagicMock, patch

from app.routers.playbooks.routes import router
from app.routers.playbooks._models import PlaybookBody, PlaybookRunBody, BatchRunBody, OperationPackCreate
from app.routers.playbooks._validation import _validate_playbook_payload
from app.routers.playbooks._data import BUILTIN_PLAYBOOKS, STEP_TEMPLATES


class TestPlaybookModels:
    def test_playbook_body_defaults(self):
        body = PlaybookBody(title="Test", description="", steps=[])
        assert body.title == "Test"

    def test_run_body_defaults(self):
        body = PlaybookRunBody()
        assert body.target == ""
        assert body.target_url == ""

    def test_batch_run_body(self):
        body = BatchRunBody(host_ids=[], parallelism=5)
        assert body.parallelism == 5

    def test_operation_pack_create(self):
        body = OperationPackCreate(name="pack1", steps=[], tags=[])
        assert body.name == "pack1"


class TestValidatePlaybook:
    def test_valid(self):
        result = _validate_playbook_payload(PlaybookBody(title="Test", description="", steps=[]), [])
        assert "ok" in result

    def test_with_steps(self):
        steps = [{"title": "Step 1", "connector_key": "ssh", "operation": "exec", "params": {}}]
        result = _validate_playbook_payload(PlaybookBody(title="Test", description="", steps=steps), [{"key": "ssh"}])
        assert "ok" in result


class TestBuiltinPlaybooks:
    def test_exists(self):
        assert isinstance(BUILTIN_PLAYBOOKS, dict)

    def test_step_templates(self):
        assert isinstance(STEP_TEMPLATES, dict)
