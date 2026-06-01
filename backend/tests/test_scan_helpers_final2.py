import pytest
from unittest.mock import MagicMock

from app.core.scan_helpers import (
    nmap_upsert_host,
    cme_upsert_host,
    cme_upsert_cred,
    cme_build_auth,
    cme_process_hosts,
    cme_process_creds,
    httpx_upsert_host,
    ffuf_severity,
    ffuf_upsert_finding,
    donpapi_upsert_cred,
    _donpapi_build_fetch_cmd,
)


class TestNmapUpsertHost:
    def test_new(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        h = {"ip": "10.0.0.1", "hostname": "srv", "os": "Linux", "ports": ["80/tcp"], "services": ["http"]}
        host, created = nmap_upsert_host(db, "p1", h)
        assert created is True
        assert db.add.called

    def test_existing(self):
        existing = MagicMock()
        existing.ports = ["443/tcp"]
        existing.services = ["https"]
        existing.hostname = ""
        existing.os = ""
        existing.status = "down"
        existing.import_source = ""
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = existing
        h = {"ip": "10.0.0.1", "hostname": "srv", "os": "Linux", "ports": ["80/tcp"], "services": ["http"]}
        host, created = nmap_upsert_host(db, "p1", h)
        assert created is False
        assert "80/tcp" in existing.ports
        assert existing.status == "up"

    def test_existing_no_override(self):
        existing = MagicMock()
        existing.ports = []
        existing.services = []
        existing.hostname = "existing"
        existing.os = "Windows"
        existing.status = "up"
        existing.import_source = "manual"
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = existing
        h = {"ip": "10.0.0.1", "hostname": "new", "os": "Linux", "ports": [], "services": []}
        nmap_upsert_host(db, "p1", h)
        assert existing.hostname == "existing"
        assert existing.os == "Windows"


class TestCmeUpsertHost:
    def test_new(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        h = {"ip": "10.0.0.1", "hostname": "srv", "ports": ["445/tcp"], "services": ["smb"]}
        host, created = cme_upsert_host(db, "p1", h)
        assert created is True

    def test_existing(self):
        existing = MagicMock()
        existing.hostname = ""
        existing.ports = []
        existing.services = []
        existing.import_source = ""
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = existing
        h = {"ip": "10.0.0.1", "hostname": "srv", "ports": ["445/tcp"], "services": ["smb"]}
        host, created = cme_upsert_host(db, "p1", h)
        assert created is False
        assert existing.hostname == "srv"


class TestCmeUpsertCred:
    def test_new(self):
        db = MagicMock()
        c = {"username": "admin", "secret": "pass", "type": "plain", "service": "smb"}
        cred, created = cme_upsert_cred(db, "p1", c, "corp", set())
        assert created is True
        assert db.add.called

    def test_duplicate(self):
        db = MagicMock()
        c = {"username": "admin", "service": "smb"}
        cred, created = cme_upsert_cred(db, "p1", c, "corp", {("admin", "smb")})
        assert created is False


class TestCmeBuildAuth:
    def test_hash(self):
        r = cme_build_auth({"hash": "abc123", "username": "admin"})
        assert "-H 'abc123'" in r

    def test_password(self):
        r = cme_build_auth({"username": "admin", "password": "pass"})
        assert "-p 'pass'" in r

    def test_username_only(self):
        r = cme_build_auth({"username": "admin"})
        assert "-u 'admin'" in r

    def test_empty(self):
        assert cme_build_auth({}) == ""


class TestCmeProcessHosts:
    def test_basic(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        hosts = [{"ip": "10.0.0.1", "hostname": "srv", "domain": "corp",
                  "ports": ["445/tcp"], "services": ["smb"]}]
        objs, domains, created = cme_process_hosts(db, "p1", hosts)
        assert created == 1
        assert domains["10.0.0.1"] == "corp"

    def test_empty(self):
        db = MagicMock()
        objs, domains, created = cme_process_hosts(db, "p1", [])
        assert created == 0


class TestCmeProcessCreds:
    def test_basic(self):
        db = MagicMock()
        creds = [{"username": "admin", "secret": "pass"}]
        objs, created = cme_process_creds(db, "p1", creds, "corp", set())
        assert created == 1


class TestHttpxUpsertHost:
    def test_new(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        r = {"host": "10.0.0.1", "port": "8080/tcp"}
        host = httpx_upsert_host(db, "p1", r)
        assert db.add.called

    def test_existing_add_port(self):
        existing = MagicMock()
        existing.ports = ["80/tcp"]
        existing.services = ["http"]
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = existing
        r = {"host": "10.0.0.1", "port": "443/tcp"}
        httpx_upsert_host(db, "p1", r)
        assert "443/tcp" in existing.ports
        assert "https" in existing.services

    def test_hostname_match(self):
        existing = MagicMock()
        existing.ports = []
        existing.services = []
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        db.query.return_value.filter.return_value.first.side_effect = [None, existing]
        r = {"host": "srv01.example.com", "port": "80/tcp"}
        host = httpx_upsert_host(db, "p1", r)


class TestFfufSeverity:
    def test_200(self):
        assert ffuf_severity(200, "") == "low"

    def test_404(self):
        assert ffuf_severity(404, "") == "info"

    def test_sensitive_path(self):
        assert ffuf_severity(200, "/admin") == "medium"
        assert ffuf_severity(200, "/.env") == "medium"

    def test_normal_path(self):
        assert ffuf_severity(200, "/page") == "low"


class TestFfufUpsertFinding:
    def test_new(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        r = {"status": 200, "url": "http://target/admin", "input": {"FUZZ": "admin"},
             "length": 1024, "words": 200}
        assert ffuf_upsert_finding(db, "p1", r, "http://target", "ts") is True
        assert db.add.called

    def test_existing(self):
        existing = MagicMock()
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = existing
        r = {"status": 200, "url": "http://target/admin", "input": {"FUZZ": "admin"}}
        assert ffuf_upsert_finding(db, "p1", r, "http://target", "ts") is False


class TestDonpapiUpsertCred:
    def test_new(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        cred = {"username": "admin", "domain": "corp", "service": "smb",
                "secret": "pass", "kind": "dpapi", "host_hint": "10.0.0.1"}
        assert donpapi_upsert_cred(db, "p1", cred, "10.0.0.1", lambda x: f"enc:{x}") is True

    def test_existing(self):
        existing = MagicMock()
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = existing
        assert donpapi_upsert_cred(db, "p1", {"username": "admin", "service": "smb"}, "t", lambda x: x) is False


class TestDonpapiBuildFetchCmd:
    def test_basic(self):
        r = _donpapi_build_fetch_cmd("/tmp/output")
        assert "tar" in r
        assert "/tmp/output" in r
