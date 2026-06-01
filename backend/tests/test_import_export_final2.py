import io
import json
import zipfile
import pytest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

TS = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    r = module_client.post("/api/projects", json={"name": "ImpExpFinal2", "added": TS, "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]
    pid = _state["pid"]
    module_client.post(f"/api/projects/{pid}/hosts",
                       json={"ip": "10.0.0.1", "hostname": "srv01", "os": "Linux", "status": "up"})
    yield


class TestMergeHostIdentity:
    def test_fills_hostname(self):
        from app.routers.import_export import _merge_host_identity
        host = MagicMock()
        host.hostname = ""
        host.domain = ""
        host.role = "unknown"
        host.is_attacker = False
        host.ip = ""
        _merge_host_identity(host, {"hostname": "srv01", "domain": "corp", "role": "server"})
        assert host.hostname == "srv01"
        assert host.domain == "corp"

    def test_is_attacker(self):
        from app.routers.import_export import _merge_host_identity
        host = MagicMock()
        host.hostname = ""
        host.domain = ""
        host.role = "server"
        host.is_attacker = False
        host.ip = ""
        _merge_host_identity(host, {"is_attacker": True})
        assert host.is_attacker is True
        assert host.role == "attacker"


class TestMergeExistingHost:
    def test_merges_all(self):
        from app.routers.import_export import _merge_existing_host
        host = MagicMock()
        host.ips = ["10.0.0.1"]
        host.ports = ["80/tcp"]
        host.services = ["http"]
        host.tags = ["tag1"]
        host.hostname = ""
        host.domain = ""
        host.role = "unknown"
        host.is_attacker = False
        host.ip = ""
        host.os = "Unknown"
        host.notes = ""
        host.status = "unknown"
        status_rank = {"unknown": 0, "up": 1, "pwned": 4}
        _merge_existing_host(host, {"ips": ["10.0.0.2"], "ports": ["443/tcp"],
                                    "services": ["https"], "tags": ["tag2"],
                                    "hostname": "srv", "domain": "corp",
                                    "role": "server", "os": "Linux",
                                    "notes": "note", "status": "up"}, status_rank)
        assert "10.0.0.2" in host.ips
        assert "443/tcp" in host.ports
        assert host.status == "up"


class TestPrepareHostData:
    def test_attacker(self):
        from app.routers.import_export import _prepare_host_data
        h = MagicMock()
        h.model_dump.return_value = {"ip": "10.0.0.1", "hostname": "kali",
                                      "is_attacker": True, "role": "attacker"}
        data, ip, hn = _prepare_host_data(h, "p1")
        assert data["status"] == "attacker"
        assert data["is_attacker"] is True


class TestImportNetworks:
    def test_basic(self):
        from app.routers.import_export import _import_networks
        db = MagicMock()
        with patch("app.routers.import_export.new_id", return_value="net1"):
            with patch("app.routers.import_export.replace_nodes"):
                with patch("app.routers.import_export.replace_edges"):
                    with patch("app.routers.import_export.replace_regions"):
                        _import_networks(db, "p1", [{"name": "Net", "nodes": [{"id": "n1"}],
                                                     "edges": [{"id": "e1"}],
                                                     "regions": [{"id": "r1"}]}])
                        assert db.add.called


class TestImportActivitiesAndPaths:
    def test_basic(self):
        from app.routers.import_export import _import_activities_and_paths
        db = MagicMock()
        hid_map = {"h1": "h_new"}
        with patch("app.routers.import_export.new_id", return_value="id1"):
            _import_activities_and_paths(db, "p1",
                                          [{"title": "f1", "host_id": "h1"}],
                                          [{"title": "obj1"}],
                                          [{"title": "act", "host_id": "h1"}],
                                          [{"id": "ap1", "name": "path"}],
                                          [{"path_id": "ap1", "step_order": 0, "label": "s1"}],
                                          hid_map)
            assert db.add.call_count >= 4


class TestImportLootsAndScope:
    def test_basic(self):
        from app.routers.import_export import _import_loots_and_scope
        db = MagicMock()
        with patch("app.routers.import_export.new_id", return_value="id1"):
            with patch("app.routers.import_export.sync_project_ip_from_scopes"):
                _import_loots_and_scope(db, "p1", [], [{"value": "10.0.0.0/24"}],
                                         [{"phase": "recon", "text": "item"}],
                                         [], {}, {}, None, set())
                assert db.add.called


class TestBatchImport:
    def test_batch_import_endpoint(self, module_client: TestClient):
        pid = _state["pid"]
        r = module_client.post(f"/api/import/{pid}",
                               json={"hosts": [{"ip": "10.0.0.5", "pid": pid, "hostname": "new_srv"}],
                                      "creds": [], "source": "test"})
        assert r.status_code == 201
        data = r.json()
        assert data["hosts_added"] >= 0


class TestExportProject:
    def test_export(self, module_client: TestClient):
        pid = _state["pid"]
        r = module_client.get(f"/api/export/{pid}")
        assert r.status_code == 200
        assert r.headers["content-type"] == "application/zip"


class TestImportProject:
    def test_import_invalid_zip(self, module_client: TestClient):
        r = module_client.post("/api/import_project",
                               files={"file": ("test.zip", b"not a zip", "application/zip")})
        assert r.status_code == 400
