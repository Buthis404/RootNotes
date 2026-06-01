"""Extended tests for import/export — helpers and edge cases."""
import io
import json
import zipfile
import pytest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

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
    r = module_client.post("/api/projects", json={"name": "IEExtTest", "added": TS, "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]
    yield


class TestImportExportHelpers:
    def test_merge_host_os_replaces_unknown(self):
        from app.routers.import_export import _merge_host_os
        host = MagicMock()
        host.os = "Unknown"
        _merge_host_os(host, "Windows Server 2022")
        assert host.os == "Windows Server 2022"

    def test_merge_host_os_keeps_longer(self):
        from app.routers.import_export import _merge_host_os
        host = MagicMock()
        host.os = "Win"
        _merge_host_os(host, "Windows Server 2022")
        assert host.os == "Windows Server 2022"

    def test_merge_host_os_skips_empty(self):
        from app.routers.import_export import _merge_host_os
        host = MagicMock()
        host.os = "Linux"
        _merge_host_os(host, "")
        assert host.os == "Linux"

    def test_merge_host_notes_appends(self):
        from app.routers.import_export import _merge_host_notes
        host = MagicMock()
        host.notes = "existing"
        _merge_host_notes(host, "new note")
        assert "new note" in host.notes

    def test_merge_host_notes_skips_duplicate(self):
        from app.routers.import_export import _merge_host_notes
        host = MagicMock()
        host.notes = "existing note"
        _merge_host_notes(host, "existing note")
        assert host.notes == "existing note"

    def test_merge_host_identity_sets_hostname(self):
        from app.routers.import_export import _merge_host_identity
        host = MagicMock()
        host.hostname = ""
        host.domain = ""
        host.role = "unknown"
        host.is_attacker = False
        host.ip = ""
        _merge_host_identity(host, {"hostname": "dc01", "domain": "corp.local"})
        assert host.hostname == "dc01"

    def test_merge_host_identity_attacker(self):
        from app.routers.import_export import _merge_host_identity
        host = MagicMock()
        host.hostname = ""
        host.domain = ""
        host.role = "unknown"
        host.is_attacker = False
        host.ip = ""
        _merge_host_identity(host, {"is_attacker": True})
        assert host.is_attacker is True
        assert host.role == "attacker"

    def test_merge_existing_host_merges(self):
        from app.routers.import_export import _merge_existing_host
        host = MagicMock()
        host.ips = []
        host.ports = []
        host.services = []
        host.tags = []
        host.hostname = ""
        host.domain = ""
        host.role = "unknown"
        host.is_attacker = False
        host.ip = ""
        host.os = "Unknown"
        host.notes = ""
        host.status = "unknown"
        status_rank = {"unknown": 0, "alive": 1, "scanned": 2, "access": 3, "pwned": 4, "owned": 5}
        _merge_existing_host(host, {
            "ips": ["10.0.0.2"], "ports": ["80/tcp"], "services": ["http"],
            "tags": ["web"], "os": "Linux", "status": "alive",
            "hostname": "web01", "domain": "", "role": "unknown", "is_attacker": False, "ip": "",
            "notes": "test",
        }, status_rank)
        assert "10.0.0.2" in host.ips
        assert host.status == "alive"


class TestPrepareHostData:
    def test_prepare_host_data(self):
        from app.routers.import_export import _prepare_host_data
        from app.schemas import HostCreate
        h = HostCreate(pid="p1", ip="10.0.0.1", hostname="test", os="Linux", status="alive")
        data, ip, hn_upper = _prepare_host_data(h, "p1")
        assert ip == "10.0.0.1"
        assert hn_upper == "TEST"


class TestBatchImportExtended:
    def test_batch_import_with_source(self, module_client: TestClient):
        r = module_client.post(
            f"/api/import/{_state['pid']}",
            json={
                "hosts": [
                    {"pid": _state["pid"], "ip": "10.99.99.1", "hostname": "src-host"},
                ],
                "creds": [],
                "source": "nmap_scan",
            },
        )
        assert r.status_code == 201
        data = r.json()
        assert data["hosts_added"] == 1

    def test_batch_import_merge_existing(self, module_client: TestClient):
        r = module_client.post(
            f"/api/import/{_state['pid']}",
            json={
                "hosts": [
                    {"pid": _state["pid"], "ip": "10.99.99.1", "hostname": "src-host-updated", "os": "Ubuntu"},
                ],
                "creds": [],
            },
        )
        assert r.status_code == 201
        data = r.json()
        assert data["hosts_added"] == 0

    def test_batch_import_attacker_host(self, module_client: TestClient):
        r = module_client.post(
            f"/api/import/{_state['pid']}",
            json={
                "hosts": [
                    {"pid": _state["pid"], "ip": "10.99.99.99", "role": "attacker"},
                ],
                "creds": [],
            },
        )
        assert r.status_code == 201
        data = r.json()
        assert data["hosts_added"] == 1


class TestExportProject:
    def test_export_returns_zip(self, module_client: TestClient):
        r = module_client.get(f"/api/export/{_state['pid']}")
        assert r.status_code == 200
        assert r.headers["content-type"] == "application/zip"
        buf = io.BytesIO(r.content)
        zf = zipfile.ZipFile(buf)
        names = set(zf.namelist())
        assert "project.json" in names

    def test_export_404(self, module_client: TestClient):
        r = module_client.get("/api/export/nonexistent")
        assert r.status_code == 404

    def test_export_zip_contains_hosts(self, module_client: TestClient):
        r = module_client.get(f"/api/export/{_state['pid']}")
        buf = io.BytesIO(r.content)
        zf = zipfile.ZipFile(buf)
        hosts_data = json.loads(zf.read("hosts.json"))
        assert isinstance(hosts_data, list)


class TestImportProject:
    def _make_zip(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("project.json", json.dumps({"name": "ImportedProj", "ip": "", "os": "Unknown", "status": "active", "added": TS, "description": ""}))
            zf.writestr("notes.json", "[]")
            zf.writestr("hosts.json", json.dumps([{"id": "h1", "ip": "10.0.0.1", "hostname": "imp-host", "os": "Linux", "status": "alive", "ports": [], "services": [], "tags": [], "notes": "", "domain": "", "role": "unknown", "is_attacker": False}]))
            zf.writestr("creds.json", json.dumps([{"id": "c1", "host": "", "username": "admin", "secret": "pass", "type": "plain", "service": "ssh", "notes": "", "tags": [], "cracked": False, "domain": "", "host_ids": [], "is_domain": False}]))
            zf.writestr("networks.json", "[]")
            zf.writestr("findings.json", "[]")
            zf.writestr("objectives.json", "[]")
            zf.writestr("host_activities.json", "[]")
            zf.writestr("attack_paths.json", "[]")
            zf.writestr("attack_steps.json", "[]")
            zf.writestr("loots.json", "[]")
            zf.writestr("scopes.json", "[]")
            zf.writestr("checklist.json", "[]")
            zf.writestr("cred_host_notes.json", "[]")
            zf.writestr("attachments.json", "[]")
        buf.seek(0)
        return buf

    def test_import_project_success(self, module_client: TestClient):
        zip_buf = self._make_zip()
        r = module_client.post(
            "/api/import_project",
            files={"file": ("test_export.zip", zip_buf, "application/zip")},
        )
        assert r.status_code == 201, r.text
        data = r.json()
        assert "project_id" in data
        assert "импорт" in data["name"]

    def test_import_invalid_zip(self, module_client: TestClient):
        r = module_client.post(
            "/api/import_project",
            files={"file": ("bad.zip", io.BytesIO(b"not a zip"), "application/zip")},
        )
        assert r.status_code == 400

    def test_import_missing_project_json(self, module_client: TestClient):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("notes.json", "[]")
        buf.seek(0)
        r = module_client.post(
            "/api/import_project",
            files={"file": ("nop.json", buf, "application/zip")},
        )
        assert r.status_code == 400
