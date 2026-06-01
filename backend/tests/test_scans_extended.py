"""Extended scans tests — parser helpers and edge cases."""
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
