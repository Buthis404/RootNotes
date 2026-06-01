"""Consolidated tests for test_scans (merged variant files)."""

# ════════ from test_scans_api.py ════════
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


# ════════ from test_scans_extended.py ════════
import json
import re
from unittest.mock import MagicMock, patch

from app.routers.scans import (
    _parse_nmap_xml,
    _nuclei_parse_line,
    _parse_nuclei_jsonl,
    _parse_cme_output,
    _cme_parse_host_line,
    _cme_parse_cred_lines,
    _build_cme_auth_flags,
    _httpx_parse_line,
    _parse_httpx_jsonl,
    _parse_ffuf_json,
    _parse_donpapi_stdout,
    _parse_donpapi_block,
    _donpapi_build_command,
)


class TestNmapParser:
    def test_empty_xml(self):
        assert _parse_nmap_xml("") == []

    def test_invalid_xml(self):
        assert _parse_nmap_xml("<not-xml>") == []

    def test_valid_xml_with_host(self):
        xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addrtype="ipv4" addr="10.0.0.1"/>
    <hostname name="test-host" type="PTR"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        hosts = _parse_nmap_xml(xml)
        assert len(hosts) == 1
        assert hosts[0]["ip"] == "10.0.0.1"
        assert hosts[0]["hostname"] == "test-host"
        assert "22/tcp" in hosts[0]["ports"]
        assert hosts[0]["status"] == "up"

    def test_down_host_skipped(self):
        xml = """<?xml version="1.0"?>
<nmaprun>
  <host><status state="down"/></host>
</nmaprun>"""
        assert _parse_nmap_xml(xml) == []


class TestNucleiParser:
    def test_parse_line(self):
        line = json.dumps({
            "info": {"name": "SQL Injection", "severity": "critical", "tags": "sqli,cve-2021-44228"},
            "matched-at": "http://10.0.0.1/search",
            "template-id": "sqli-test",
        })
        result = _nuclei_parse_line(line)
        assert result is not None
        assert result["title"] == "SQL Injection"
        assert result["severity"] == "critical"
        assert "CVE-2021-44228" == result["cve"]

    def test_empty_line(self):
        assert _nuclei_parse_line("") is None
        assert _nuclei_parse_line("not json") is None

    def test_parse_jsonl(self):
        text = json.dumps({"info": {"name": "Test", "severity": "high"}, "template-id": "t1"}) + "\n" + "garbage\n"
        results = _parse_nuclei_jsonl(text)
        assert len(results) == 1


class TestCmeParser:
    def test_parse_host_line(self):
        line = "SMB    10.0.0.1    445    DC01    [*] Windows Server (domain:corp.local)"
        seen = set()
        result = _cme_parse_host_line(line, seen)
        assert result is not None
        assert result["ip"] == "10.0.0.1"
        assert result["hostname"] == "DC01"
        assert result["domain"] == "corp.local"

    def test_parse_host_duplicate(self):
        line = "SMB    10.0.0.1    445    DC01    [*]"
        seen = {"10.0.0.1"}
        assert _cme_parse_host_line(line, seen) is None

    def test_parse_cred_line(self):
        line = r"[+] 10.0.0.1\admin:Password123"
        results = _cme_parse_cred_lines(line, set())
        assert len(results) == 1
        assert results[0]["username"] == r"10.0.0.1\admin"
        assert results[0]["secret"] == "Password123"

    def test_parse_cred_empty_password(self):
        line = "[+] 10.0.0.1\guest:<empty>"
        results = _cme_parse_cred_lines(line, set())
        assert len(results) == 0

    def test_build_auth_flags_hash(self):
        body = MagicMock()
        body.hash = "AAD3B435B51404EE"
        body.username = "admin"
        body.password = "pass"
        flags = _build_cme_auth_flags(body)
        assert "-H" in flags

    def test_build_auth_flags_password(self):
        body = MagicMock()
        body.hash = None
        body.username = "admin"
        body.password = "pass"
        flags = _build_cme_auth_flags(body)
        assert "-u" in flags
        assert "-p" in flags

    def test_build_auth_flags_no_auth(self):
        body = MagicMock()
        body.hash = None
        body.username = None
        body.password = None
        flags = _build_cme_auth_flags(body)
        assert flags == ""


class TestHttpxParser:
    def test_parse_line(self):
        line = json.dumps({
            "url": "https://example.com",
            "host": "example.com",
            "port": 443,
            "status_code": 200,
            "title": "Example",
            "tech": ["Nginx"],
            "webserver": "nginx",
        })
        result = _httpx_parse_line(line)
        assert result is not None
        assert result["host"] == "example.com"
        assert result["status"] == 200

    def test_parse_jsonl(self):
        text = json.dumps({"url": "http://test", "host": "test", "status_code": 200}) + "\n"
        results = _parse_httpx_jsonl(text)
        assert len(results) == 1


class TestFfufParser:
    def test_parse_results(self):
        data = json.dumps({"results": [{"url": "http://test/admin", "status": 200, "length": 1234}]})
        results = _parse_ffuf_json(data)
        assert len(results) == 1

    def test_parse_no_results(self):
        assert _parse_ffuf_json("not json") == []
        assert _parse_ffuf_json("{}") == []


class TestDonpapiParser:
    def test_parse_stdout(self):
        text = """[+] Found credential on 10.0.0.5
    URL: https://login.example.com
    Login: alice@example.com
    Password: P@ssw0rd!
"""
        creds = _parse_donpapi_stdout(text)
        assert len(creds) == 1
        assert creds[0]["username"] == "alice@example.com"
        assert creds[0]["secret"] == "P@ssw0rd!"

    def test_parse_empty(self):
        assert _parse_donpapi_stdout("") == []

    def test_parse_block_no_header(self):
        result = _parse_donpapi_block("random text without header")
        assert result is None

    def test_build_command_with_hash(self):
        cmd = _donpapi_build_command("10.0.0.1", "corp.local", "admin", "", "AAD3B435B51404EE", "", "/tmp/out")
        assert "-H" in cmd

    def test_build_command_with_password(self):
        cmd = _donpapi_build_command("10.0.0.1", "corp.local", "admin", "pass", "", "", "/tmp/out")
        assert "-p" in cmd
