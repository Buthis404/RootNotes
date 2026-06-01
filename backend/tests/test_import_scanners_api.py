"""
Tests for scanner import endpoints: Nessus and Burp Suite.
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
    r = module_client.post("/api/projects", json={"name": "ScannerImportTest", "added": TS, "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]
    yield
    module_client.post("/api/auth/logout")


NESSUS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<NessusClientData_v2>
<Report name="Test Scan">
<ReportHost name="10.20.20.1">
  <HostProperties>
    <tag name="host-ip">10.20.20.1</tag>
    <tag name="host-fqdn">nessus-srv.test.local</tag>
    <tag name="operating-system">Linux 5.x</tag>
  </HostProperties>
  <ReportItem pluginName="SSH Server Supports Weak Algorithms" severity="2" port="22" protocol="tcp">
    <description>Weak SSH algorithms detected</description>
    <solution>Upgrade SSH config</solution>
    <cvss3_base_score>5.3</cvss3_base_score>
  </ReportItem>
  <ReportItem pluginName="HTTP Missing Security Headers" severity="1" port="80" protocol="tcp">
    <description>Missing headers</description>
    <solution>Add headers</solution>
  </ReportItem>
</ReportHost>
</Report>
</NessusClientData_v2>"""

NESSUS_MULTI_HOST = """<?xml version="1.0" encoding="UTF-8"?>
<NessusClientData_v2>
<Report name="Multi">
<ReportHost name="10.20.20.10">
  <HostProperties>
    <tag name="host-ip">10.20.20.10</tag>
  </HostProperties>
  <ReportItem pluginName="Critical Vuln" severity="4" port="443" protocol="tcp">
    <description>RCE</description>
    <solution>Patch</solution>
    <cve>CVE-2024-1234</cve>
    <cvss3_base_score>9.8</cvss3_base_score>
  </ReportItem>
</ReportHost>
<ReportHost name="10.20.20.11">
  <HostProperties>
    <tag name="host-ip">10.20.20.11</tag>
    <tag name="host-fqdn">second-host.test.local</tag>
  </HostProperties>
</ReportHost>
</Report>
</NessusClientData_v2>"""

BURP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<issues>
  <issue>
    <host ip="10.30.30.1">10.30.30.1</host>
    <name>SQL Injection</name>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <issueDetail>Input not sanitized</issueDetail>
    <remediationDetail>Use parameterized queries</remediationDetail>
  </issue>
  <issue>
    <host ip="10.30.30.1">10.30.30.1</host>
    <name>XSS Reflected</name>
    <severity>Medium</severity>
    <confidence>Firm</confidence>
    <issueBackground>Cross-site scripting</issueBackground>
    <remediationBackground>Encode output</remediationBackground>
  </issue>
  <issue>
    <host ip="10.30.30.2">10.30.30.2</host>
    <name>SSL Certificate Error</name>
    <severity>Low</severity>
    <confidence>Certain</confidence>
  </issue>
</issues>"""


class TestNessusImport:
    def test_import_nessus(self, module_client: TestClient):
        r = module_client.post(
            f"/api/projects/{_state['pid']}/import/nessus",
            files={"file": ("scan.nessus", NESSUS_XML.encode(), "text/xml")},
        )
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["hosts_created"] >= 1
        assert data["findings_created"] >= 1

    def test_import_nessus_findings_created(self, module_client: TestClient):
        r = module_client.get("/api/findings", params={"pid": _state["pid"]})
        assert r.status_code == 200
        titles = [f["title"] for f in r.json()]
        assert "SSH Server Supports Weak Algorithms" in titles

    def test_import_nessus_host_created(self, module_client: TestClient):
        r = module_client.get("/api/hosts", params={"pid": _state["pid"]})
        assert r.status_code == 200
        ips = [h["ip"] for h in r.json()]
        assert "10.20.20.1" in ips

    def test_import_nessus_multi_host(self, module_client: TestClient):
        r = module_client.post(
            f"/api/projects/{_state['pid']}/import/nessus",
            files={"file": ("multi.nessus", NESSUS_MULTI_HOST.encode(), "text/xml")},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["hosts_created"] >= 2
        assert data["findings_created"] >= 1

    def test_import_nessus_dedup(self, module_client: TestClient):
        r = module_client.post(
            f"/api/projects/{_state['pid']}/import/nessus",
            files={"file": ("dup.nessus", NESSUS_XML.encode(), "text/xml")},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["findings_skipped"] >= 1

    def test_import_nessus_invalid_xml(self, module_client: TestClient):
        r = module_client.post(
            f"/api/projects/{_state['pid']}/import/nessus",
            files={"file": ("bad.xml", b"<not-nessus/>", "text/xml")},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["hosts_created"] == 0


class TestBurpImport:
    def test_import_burp(self, module_client: TestClient):
        r = module_client.post(
            f"/api/projects/{_state['pid']}/import/burp",
            files={"file": ("burp.xml", BURP_XML.encode(), "text/xml")},
        )
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["hosts_created"] >= 1
        assert data["findings_created"] >= 2

    def test_import_burp_hosts(self, module_client: TestClient):
        r = module_client.get("/api/hosts", params={"pid": _state["pid"]})
        ips = [h["ip"] for h in r.json()]
        assert "10.30.30.1" in ips
        assert "10.30.30.2" in ips

    def test_import_burp_findings(self, module_client: TestClient):
        r = module_client.get("/api/findings", params={"pid": _state["pid"]})
        titles = [f["title"] for f in r.json()]
        assert "SQL Injection" in titles
        assert "XSS Reflected" in titles

    def test_import_burp_dedup(self, module_client: TestClient):
        r = module_client.post(
            f"/api/projects/{_state['pid']}/import/burp",
            files={"file": ("burp2.xml", BURP_XML.encode(), "text/xml")},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["findings_skipped"] >= 2


class TestNessusHelpers:
    def test_parse_nessus_host_tags(self):
        from app.routers.import_scanners import _parse_nessus_host_tags
        import xml.etree.ElementTree as ET
        el = ET.fromstring("""<ReportHost name="10.0.0.1">
            <tag name="host-ip">10.0.0.1</tag>
            <tag name="host-fqdn">srv.test.local</tag>
            <tag name="operating-system">Linux</tag>
        </ReportHost>""")
        ip, hn, os_str = _parse_nessus_host_tags(el)
        assert ip == "10.0.0.1"
        assert hn == "srv.test.local"
        assert os_str == "Linux"

    def test_strip_html(self):
        from app.routers.import_scanners import _strip_html
        assert _strip_html("<b>bold</b> text") == "bold text"
        assert _strip_html("") == ""
        assert _strip_html("no html") == "no html"


class TestBurpHelpers:
    def test_parse_burp_issue_ip(self):
        from app.routers.import_scanners import _parse_burp_issue_ip
        import xml.etree.ElementTree as ET
        el = ET.fromstring('<issue><host ip="10.0.0.1">10.0.0.1</host></issue>')
        assert _parse_burp_issue_ip(el) == "10.0.0.1"

    def test_parse_burp_issue_title(self):
        from app.routers.import_scanners import _parse_burp_issue_title
        import xml.etree.ElementTree as ET
        el = ET.fromstring('<issue><name>SQL Injection</name></issue>')
        assert _parse_burp_issue_title(el) == "SQL Injection"

    def test_parse_burp_issue_severity(self):
        from app.routers.import_scanners import _parse_burp_issue_severity
        import xml.etree.ElementTree as ET
        el = ET.fromstring('<issue><severity>High</severity></issue>')
        assert _parse_burp_issue_severity(el) == "high"

    def test_parse_burp_issue_no_ip(self):
        from app.routers.import_scanners import _parse_burp_issue_ip
        import xml.etree.ElementTree as ET
        el = ET.fromstring('<issue></issue>')
        assert _parse_burp_issue_ip(el) == ""
