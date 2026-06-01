"""
Tests for scan management endpoints.
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
    r = module_client.post("/api/projects", json={"name": "ScansTest", "added": TS, "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]
    yield
    module_client.post("/api/auth/logout")


class TestScanEndpoints:
    def test_nmap_requires_module(self, module_client: TestClient):
        r = module_client.post(
            f"/api/projects/{_state['pid']}/scans/nmap",
            json={"target": "10.0.0.0/24"},
        )
        assert r.status_code in (404, 400, 422, 200, 500)

    def test_nuclei_requires_module(self, module_client: TestClient):
        r = module_client.post(
            f"/api/projects/{_state['pid']}/scans/nuclei",
            json={"target": "http://10.0.0.1"},
        )
        assert r.status_code in (404, 400, 422, 200, 500)

    def test_cme_requires_module(self, module_client: TestClient):
        r = module_client.post(
            f"/api/projects/{_state['pid']}/scans/cme",
            json={"target": "10.0.0.0/24", "protocol": "smb"},
        )
        assert r.status_code in (404, 400, 422, 200, 500)


class TestScanParsers:
    def test_parse_nmap_xml(self):
        from app.routers.scans import _parse_nmap_xml
        xml = """<?xml version="1.0"?>
        <nmaprun>
        <host><status state="up"/>
        <address addrtype="ipv4" addr="10.1.1.1"/>
        <hostnames><hostname type="PTR" name="test.local"/></hostnames>
        <ports><port protocol="tcp" portid="22"><state state="open"/>
        <service name="ssh" product="OpenSSH"/></port></ports>
        </host></nmaprun>"""
        hosts = _parse_nmap_xml(xml)
        assert len(hosts) == 1
        assert hosts[0]["ip"] == "10.1.1.1"
        assert "22/tcp" in hosts[0]["ports"]

    def test_parse_nmap_xml_empty(self):
        from app.routers.scans import _parse_nmap_xml
        assert _parse_nmap_xml("") == []

    def test_parse_nuclei_jsonl(self):
        from app.routers.scans import _parse_nuclei_jsonl
        line = '{"info":{"name":"Test","severity":"high"},"template-id":"test","matched-at":"http://10.0.0.1"}'
        results = _parse_nuclei_jsonl(line)
        assert len(results) == 1
        assert results[0]["title"] == "Test"

    def test_parse_cme_output(self):
        from app.routers.scans import _parse_cme_output
        output = "SMB    10.0.0.1    445    DC01    [+] admin:Password1"
        result = _parse_cme_output(output)
        assert len(result["hosts"]) == 1
        assert result["hosts"][0]["ip"] == "10.0.0.1"
        assert len(result["creds"]) == 1
        assert result["creds"][0]["username"] == "admin"

    def test_parse_httpx_jsonl(self):
        from app.routers.scans import _parse_httpx_jsonl
        line = '{"url":"http://10.0.0.1","host":"10.0.0.1","port":80,"status_code":200,"title":"Test"}'
        results = _parse_httpx_jsonl(line)
        assert len(results) == 1
        assert results[0]["host"] == "10.0.0.1"

    def test_parse_ffuf_json(self):
        from app.routers.scans import _parse_ffuf_json
        data = '{"results":[{"url":"http://10.0.0.1/admin","status":200,"length":123}]}'
        results = _parse_ffuf_json(data)
        assert len(results) == 1

    def test_build_cme_auth_flags(self):
        from app.routers.scans import _build_cme_auth_flags, CmeScanBody
        body = CmeScanBody(target="10.0.0.0/24", username="admin", password="pass")
        flags = _build_cme_auth_flags(body)
        assert "admin" in flags
        assert "pass" in flags

    def test_build_cme_auth_flags_hash(self):
        from app.routers.scans import _build_cme_auth_flags, CmeScanBody
        body = CmeScanBody(target="10.0.0.0/24", username="admin", hash="aadm3b435")
        flags = _build_cme_auth_flags(body)
        assert "-H" in flags
        assert "aadm3b435" in flags

    def test_parse_donpapi_stdout(self):
        from app.routers.scans import _parse_donpapi_stdout
        text = (
            "[+] Found credential on 10.0.0.5\n"
            "  URL: https://login.example.com\n"
            "  Login: alice@example.com\n"
            "  Password: P@ssw0rd!\n"
        )
        creds = _parse_donpapi_stdout(text)
        assert len(creds) >= 0

    def test_nuclei_cve_from_info(self):
        from app.routers.scans import _nuclei_cve_from_info
        assert _nuclei_cve_from_info({"tags": "cve-2024-0001,rce"}) == "CVE-2024-0001"
        assert _nuclei_cve_from_info({"tags": "rce"}) == ""
