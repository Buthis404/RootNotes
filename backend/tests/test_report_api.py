"""
Tests for report generation endpoints (HTML and PDF).
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
    r = module_client.post("/api/projects", json={"name": "ReportTest", "added": TS, "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]

    module_client.post("/api/hosts", json={
        "pid": _state["pid"], "ip": "10.40.40.1", "hostname": "report-host",
        "os": "Windows Server 2022", "status": "pwned", "ports": ["445/tcp", "3389/tcp"],
        "services": ["smb", "rdp"], "tags": ["dc"], "domain": "corp.local",
        "role": "domain_controller",
    })
    module_client.post("/api/findings", json={
        "pid": _state["pid"], "title": "Report Critical Vuln", "severity": "critical",
        "status": "open", "description": "RCE found", "proof": "exploit proof",
        "recommendation": "Patch immediately", "cve": "CVE-2024-9999", "cvss": "9.8", "ts": TS,
    })
    module_client.post("/api/findings", json={
        "pid": _state["pid"], "title": "Report Medium Vuln", "severity": "medium",
        "status": "open", "description": "Info disclosure", "ts": TS,
    })
    module_client.post("/api/creds", json={
        "pid": _state["pid"], "username": "admin", "secret": "PwnedPass!",
        "type": "plain", "host": "10.40.40.1", "cracked": True,
    })
    yield
    module_client.post("/api/auth/logout")


class TestHtmlReport:
    def test_generate_html_report(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/report/html")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]

    def test_html_contains_project_name(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/report/html")
        assert b"ReportTest" in r.content

    def test_html_contains_findings(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/report/html")
        assert b"Report Critical Vuln" in r.content

    def test_html_contains_hosts(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/report/html")
        assert b"10.40.40.1" in r.content

    def test_html_contains_creds(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/report/html")
        assert b"admin" in r.content

    def test_html_report_404(self, module_client: TestClient):
        r = module_client.get("/api/projects/nonexistent/report/html")
        assert r.status_code in (404, 500)


class TestPdfReport:
    def test_generate_pdf_report(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/report/pdf")
        assert r.status_code == 200
        ct = r.headers.get("content-type", "")
        assert "pdf" in ct or "html" in ct


class TestReportHelpers:
    def test_sev_badge(self):
        from app.routers.report import _sev_badge
        badge = _sev_badge("critical")
        assert "critical" in badge.lower()
        assert "<span" in badge

    def test_risk_label_color(self):
        from app.routers.report import _risk_label_color
        label, color = _risk_label_color(35)
        assert label == "Critical"
        label2, _ = _risk_label_color(0)
        assert label2 == "None"
        label3, _ = _risk_label_color(10)
        assert label3 == "Medium"

    def test_host_display_str(self):
        from app.routers.report import _host_display_str

        class H:
            ip = "10.0.0.1"
            hostname = "test"

        assert "10.0.0.1" in _host_display_str(H())
        assert "test" in _host_display_str(H())

    def test_host_display_str_none(self):
        from app.routers.report import _host_display_str
        assert _host_display_str(None) == ""

    def test_compute_sev_counts(self):
        from app.routers.report import _compute_sev_counts

        class F:
            def __init__(self, sev):
                self.severity = sev

        counts = _compute_sev_counts([F("critical"), F("critical"), F("high")])
        assert counts["critical"] == 2
        assert counts["high"] == 1
        assert counts["medium"] == 0

    def test_classify_report_hosts(self):
        from app.routers.report import _classify_report_hosts

        class H:
            def __init__(self, is_attacker, status):
                self.is_attacker = is_attacker
                self.status = status

        class C:
            cracked = True

        non_att, pwned, cracked = _classify_report_hosts(
            [H(False, "pwned"), H(True, "attacker"), H(False, "alive")], [C()]
        )
        assert len(non_att) == 2
        assert len(pwned) == 1
        assert len(cracked) == 1
