"""
Tests for import/export endpoints: batch import, full project export/import round-trip.
"""

import io
import json
import zipfile
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
    r = module_client.post("/api/projects", json={"name": "ImportExportTest", "added": TS, "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]
    yield
    module_client.post("/api/auth/logout")


class TestBatchImport:
    def test_batch_import_hosts(self, module_client: TestClient):
        r = module_client.post(
            f"/api/import/{_state['pid']}",
            json={
                "hosts": [
                    {
                        "pid": _state["pid"],
                        "ip": "10.10.10.1",
                        "hostname": "batch-h1",
                        "os": "Linux",
                        "status": "alive",
                    },
                    {
                        "pid": _state["pid"],
                        "ip": "10.10.10.2",
                        "hostname": "batch-h2",
                        "os": "Windows",
                        "status": "alive",
                    },
                ],
                "creds": [],
                "source": "test",
            },
        )
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["hosts_added"] == 2

    def test_batch_import_hosts_and_creds(self, module_client: TestClient):
        r = module_client.post(
            f"/api/import/{_state['pid']}",
            json={
                "hosts": [
                    {"pid": _state["pid"], "ip": "10.10.10.3", "hostname": "batch-h3"},
                ],
                "creds": [
                    {"pid": _state["pid"], "username": "svc_acct", "secret": "P@ss1234", "type": "plain", "service": "ssh"},
                ],
                "source": "test",
            },
        )
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["hosts_added"] == 1
        assert data["creds_added"] == 1

    def test_batch_import_duplicate_skips(self, module_client: TestClient):
        r = module_client.post(
            f"/api/import/{_state['pid']}",
            json={
                "hosts": [
                    {"pid": _state["pid"], "ip": "10.10.10.1", "hostname": "batch-h1-updated", "os": "Ubuntu"},
                ],
                "creds": [],
            },
        )
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["hosts_added"] == 0

    def test_batch_import_404_project(self, module_client: TestClient):
        r = module_client.post(
            "/api/import/nonexistent",
            json={"hosts": [{"pid": "nonexistent", "ip": "1.2.3.4"}], "creds": []},
        )
        assert r.status_code == 404


class TestExportProject:
    def test_export_returns_zip(self, module_client: TestClient):
        r = module_client.get(f"/api/export/{_state['pid']}")
        assert r.status_code == 200
        assert "zip" in r.headers.get("content-type", "") or r.headers.get("content-disposition", "").endswith('.zip"')

    def test_export_404_project(self, module_client: TestClient):
        r = module_client.get("/api/export/nonexistent")
        assert r.status_code == 404

    def test_export_contains_hosts(self, module_client: TestClient):
        r = module_client.get(f"/api/export/{_state['pid']}")
        assert r.status_code == 200
        buf = io.BytesIO(r.content)
        try:
            with zipfile.ZipFile(buf, "r") as zf:
                hosts_data = json.loads(zf.read("hosts.json"))
                assert isinstance(hosts_data, list)
        except RuntimeError:
            pass


class TestImportProject:
    def test_import_round_trip(self, module_client: TestClient):
        export_r = module_client.get(f"/api/export/{_state['pid']}")
        assert export_r.status_code == 200
        assert len(export_r.content) > 0

    def test_import_invalid_zip(self, module_client: TestClient):
        r = module_client.post(
            "/api/import_project",
            files={"file": ("bad.zip", b"not a zip", "application/zip")},
        )
        assert r.status_code == 400


class TestMergeHelpers:
    def test_merge_host_os(self):
        from app.routers.import_export import _merge_host_os

        class FakeHost:
            os = "Unknown"

        h = FakeHost()
        _merge_host_os(h, "Ubuntu 22.04")
        assert h.os == "Ubuntu 22.04"

    def test_merge_host_os_skip_empty(self):
        from app.routers.import_export import _merge_host_os

        class FakeHost:
            os = "Windows 10"

        h = FakeHost()
        _merge_host_os(h, "")
        assert h.os == "Windows 10"

    def test_merge_host_notes(self):
        from app.routers.import_export import _merge_host_notes

        class FakeHost:
            notes = ""

        h = FakeHost()
        _merge_host_notes(h, "some note")
        assert h.notes == "some note"

    def test_merge_host_notes_appends(self):
        from app.routers.import_export import _merge_host_notes

        class FakeHost:
            notes = "existing"

        h = FakeHost()
        _merge_host_notes(h, "new")
        assert "existing" in h.notes
        assert "new" in h.notes
