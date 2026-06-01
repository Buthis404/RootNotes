"""Comprehensive tests for the CSV export API endpoints."""
import csv
import io
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
    r = module_client.post("/api/projects", json={"name": "ExportTest", "added": TS, "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]

    r = module_client.post("/api/hosts", json={
        "pid": _state["pid"], "ip": "10.5.5.5", "hostname": "export-host",
        "os": "Linux", "status": "alive", "ports": ["22/tcp", "80/tcp"],
        "services": ["ssh", "http"], "tags": ["web"], "notes": "Test host",
    })
    assert r.status_code == 201
    _state["hid"] = r.json()["id"]

    r = module_client.post("/api/findings", json={
        "pid": _state["pid"], "title": "Export Finding", "severity": "high",
        "cvss": "7.5", "cve": "CVE-2024-0001", "status": "open",
        "description": "Desc", "proof": "Proof", "recommendation": "Fix it", "ts": TS,
    })
    assert r.status_code == 201
    _state["fid"] = r.json()["id"]

    r = module_client.post("/api/creds", json={
        "pid": _state["pid"], "username": "exportuser", "secret": "ExportPass123!",
        "type": "plain", "host": "10.5.5.5",
    })
    assert r.status_code == 201
    _state["cid"] = r.json()["id"]

    yield
    module_client.post("/api/auth/logout")


class TestExportHosts:
    def test_export_hosts_csv(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/export/hosts.csv")
        assert r.status_code == 200
        assert "text/csv" in r.headers["content-type"]
        reader = csv.reader(io.StringIO(r.text))
        rows = list(reader)
        assert rows[0] == ["ip", "hostname", "os", "status", "role", "domain", "ports", "services", "tags", "notes"]
        data_rows = rows[1:]
        ips = [row[0] for row in data_rows]
        assert "10.5.5.5" in ips

    def test_export_hosts_has_data(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/export/hosts.csv")
        lines = r.text.strip().split("\n")
        assert len(lines) >= 2


class TestExportFindings:
    def test_export_findings_csv(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/export/findings.csv")
        assert r.status_code == 200
        assert "text/csv" in r.headers["content-type"]
        reader = csv.reader(io.StringIO(r.text))
        rows = list(reader)
        assert rows[0] == ["title", "severity", "cvss", "cve", "status", "description", "proof", "recommendation"]
        data_rows = rows[1:]
        titles = [row[0] for row in data_rows]
        assert "Export Finding" in titles

    def test_export_findings_contains_severity(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/export/findings.csv")
        reader = csv.reader(io.StringIO(r.text))
        rows = list(reader)
        for row in rows[1:]:
            if row[0] == "Export Finding":
                assert row[1] == "high"
                assert row[3] == "CVE-2024-0001"


class TestExportCreds:
    def test_export_creds_csv(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/export/creds.csv")
        assert r.status_code == 200
        assert "text/csv" in r.headers["content-type"]
        reader = csv.reader(io.StringIO(r.text))
        rows = list(reader)
        assert rows[0] == ["username", "service", "host", "domain", "type", "cracked", "tags", "notes"]
        data_rows = rows[1:]
        usernames = [row[0] for row in data_rows]
        assert "exportuser" in usernames

    def test_export_creds_no_secret(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/export/creds.csv")
        reader = csv.reader(io.StringIO(r.text))
        rows = list(reader)
        header = rows[0]
        assert "secret" not in header
        for col in header:
            assert col != "secret"
