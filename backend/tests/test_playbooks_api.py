"""Playbooks API integration tests — listing, templates, runs, packs, import/export."""
import io
import json
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
    r = module_client.post("/api/projects", json={"name": "Playbooks Test", "added": TS, "status": "active"})
    assert r.status_code == 201, r.text
    _state["pid"] = r.json()["id"]
    yield
    module_client.post("/api/auth/logout")


class TestListPlaybooks:
    def test_list_returns_builtin(self, module_client: TestClient):
        r = module_client.get("/api/playbooks")
        assert r.status_code == 200
        data = r.json()
        assert "playbooks" in data
        assert len(data["playbooks"]) > 0
        builtin_ids = [p["id"] for p in data["playbooks"] if not p.get("editable", True)]
        assert len(builtin_ids) > 0

    def test_step_templates(self, module_client: TestClient):
        r = module_client.get("/api/playbooks/step-templates")
        assert r.status_code == 200
        data = r.json()
        assert "templates" in data
        assert len(data["templates"]) > 0


class TestValidatePlaybook:
    def test_validate_returns_structure(self, module_client: TestClient):
        r = module_client.post("/api/playbooks/validate", json={
            "title": "Test PB",
            "description": "desc",
            "steps": [
                {"title": "Nmap scan", "connector_key": "nmap", "operation": "scan", "params": {}},
            ],
        })
        assert r.status_code == 200
        data = r.json()
        assert "ok" in data
        assert "errors" in data
        assert "warnings" in data

    def test_validate_empty_title_errors(self, module_client: TestClient):
        r = module_client.post("/api/playbooks/validate", json={
            "title": "",
            "steps": [],
        })
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is False
        assert any("Title" in e for e in data["errors"])

    def test_validate_no_steps_errors(self, module_client: TestClient):
        r = module_client.post("/api/playbooks/validate", json={
            "title": "Empty PB",
            "steps": [],
        })
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is False
        assert any("step" in e.lower() for e in data["errors"])


class TestPlaybookRuns:
    def test_run_builtin_playbook(self, module_client: TestClient):
        pid = _state["pid"]
        r = module_client.post(f"/api/projects/{pid}/playbooks/topology-refresh/run", json={
            "target": "10.0.0.1",
        })
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["ok"] is True
        assert data["playbook_run"]["id"]
        assert data["playbook_run"]["status"] == "queued"
        _state["run_id"] = data["playbook_run"]["id"]

    def test_list_playbook_runs(self, module_client: TestClient):
        pid = _state["pid"]
        r = module_client.get(f"/api/projects/{pid}/playbook-runs")
        assert r.status_code == 200
        data = r.json()
        assert "runs" in data
        ids = [run["id"] for run in data["runs"]]
        assert _state["run_id"] in ids

    def test_list_runs_with_limit(self, module_client: TestClient):
        pid = _state["pid"]
        r = module_client.get(f"/api/projects/{pid}/playbook-runs?limit=1")
        assert r.status_code == 200
        assert len(r.json()["runs"]) <= 1

    def test_get_playbook_run(self, module_client: TestClient):
        pid = _state["pid"]
        r = module_client.get(f"/api/projects/{pid}/playbook-runs/{_state['run_id']}")
        assert r.status_code == 200
        assert r.json()["id"] == _state["run_id"]

    def test_get_nonexistent_run_404(self, module_client: TestClient):
        pid = _state["pid"]
        r = module_client.get(f"/api/projects/{pid}/playbook-runs/pbr_nonexistent")
        assert r.status_code == 404

    def test_run_nonexistent_playbook_404(self, module_client: TestClient):
        pid = _state["pid"]
        r = module_client.post(f"/api/projects/{pid}/playbooks/pb_nonexistent/run", json={"target": "10.0.0.1"})
        assert r.status_code == 404

    def test_cancel_playbook_run(self, module_client: TestClient):
        pid = _state["pid"]
        r = module_client.post(f"/api/projects/{pid}/playbooks/topology-refresh/run", json={"target": "10.0.0.2"})
        assert r.status_code == 201, r.text
        run_id = r.json()["playbook_run"]["id"]
        r = module_client.post(f"/api/projects/{pid}/playbook-runs/{run_id}/cancel")
        assert r.status_code == 200
        assert r.json()["status"] == "cancelled"

    def test_cancel_terminal_run_400(self, module_client: TestClient):
        pid = _state["pid"]
        r = module_client.post(f"/api/projects/{pid}/playbooks/topology-refresh/run", json={"target": "10.0.0.3"})
        assert r.status_code == 201
        run_id = r.json()["playbook_run"]["id"]
        module_client.post(f"/api/projects/{pid}/playbook-runs/{run_id}/cancel")
        r = module_client.post(f"/api/projects/{pid}/playbook-runs/{run_id}/cancel")
        assert r.status_code == 400

    def test_cancel_nonexistent_run_404(self, module_client: TestClient):
        pid = _state["pid"]
        r = module_client.post(f"/api/projects/{pid}/playbook-runs/pbr_nonexistent/cancel")
        assert r.status_code == 404

    def test_rerun_playbook_run(self, module_client: TestClient):
        pid = _state["pid"]
        r = module_client.post(f"/api/projects/{pid}/playbooks/topology-refresh/run", json={"target": "10.0.0.4"})
        assert r.status_code == 201, r.text
        run_id = r.json()["playbook_run"]["id"]
        module_client.post(f"/api/projects/{pid}/playbook-runs/{run_id}/cancel")
        r = module_client.post(f"/api/projects/{pid}/playbook-runs/{run_id}/rerun")
        assert r.status_code == 201
        data = r.json()
        assert data["ok"] is True
        assert data["playbook_run"]["id"] != run_id

    def test_rerun_nonexistent_404(self, module_client: TestClient):
        pid = _state["pid"]
        r = module_client.post(f"/api/projects/{pid}/playbook-runs/pbr_nonexistent/rerun")
        assert r.status_code == 404


class TestPlaybookExportImport:
    def test_export_custom_playbooks(self, module_client: TestClient):
        r = module_client.get("/api/playbooks/custom/export")
        assert r.status_code == 200
        assert "custom_playbooks" in r.headers.get("content-disposition", "")
        data = json.loads(r.text)
        assert "playbooks" in data

    def test_import_custom_playbooks(self, module_client: TestClient):
        payload = json.dumps({
            "format": "rootnotes-playbooks",
            "version": "1",
            "playbooks": [
                {"title": "Imported PB", "description": "desc", "steps": [
                    {"title": "Step 1", "connector_key": "nmap", "operation": "scan", "params": {}},
                ]},
            ],
        }).encode()
        r = module_client.post(
            "/api/playbooks/custom/import",
            files={"file": ("playbooks.json", io.BytesIO(payload), "application/json")},
        )
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["created"] >= 1
        assert data["skipped"] >= 0

    def test_import_duplicate_skips(self, module_client: TestClient):
        payload = json.dumps({
            "format": "rootnotes-playbooks",
            "version": "1",
            "playbooks": [
                {"title": "Imported PB", "description": "desc", "steps": []},
            ],
        }).encode()
        r = module_client.post(
            "/api/playbooks/custom/import",
            files={"file": ("playbooks.json", io.BytesIO(payload), "application/json")},
        )
        assert r.status_code == 201
        assert r.json()["skipped"] >= 1

    def test_import_empty_list(self, module_client: TestClient):
        payload = json.dumps({"playbooks": []}).encode()
        r = module_client.post(
            "/api/playbooks/custom/import",
            files={"file": ("playbooks.json", io.BytesIO(payload), "application/json")},
        )
        assert r.status_code == 201
        assert r.json()["created"] == 0


class TestOperationPacks:
    def test_list_packs_includes_builtin(self, module_client: TestClient):
        r = module_client.get("/api/playbooks/packs")
        assert r.status_code == 200
        data = r.json()
        assert "packs" in data
        builtin_ids = [p["id"] for p in data["packs"] if p["id"].startswith("pack_builtin")]
        assert len(builtin_ids) > 0

    def test_create_pack(self, module_client: TestClient):
        r = module_client.post("/api/playbooks/packs", json={
            "name": "Test Pack",
            "description": "A test pack",
            "steps": [
                {"title": "Step", "connector_key": "nmap", "operation": "scan", "params": {}},
            ],
            "tags": ["test"],
        })
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["name"] == "Test Pack"
        assert data["id"]
        _state["pack_id"] = data["id"]

    def test_list_packs_includes_custom(self, module_client: TestClient):
        r = module_client.get("/api/playbooks/packs")
        assert r.status_code == 200
        ids = [p["id"] for p in r.json()["packs"]]
        assert _state["pack_id"] in ids

    def test_delete_pack(self, module_client: TestClient):
        r = module_client.delete(f"/api/playbooks/packs/{_state['pack_id']}")
        assert r.status_code == 204

    def test_delete_nonexistent_pack_404(self, module_client: TestClient):
        r = module_client.delete("/api/playbooks/packs/pack_nonexistent")
        assert r.status_code == 404
