import pytest
from unittest.mock import MagicMock, patch

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
    def test_new_host(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        with patch("app.core.scan_helpers.new_id", return_value="h1"):
            h, created = nmap_upsert_host(db, "p1", {"ip": "10.0.0.1", "ports": [22], "services": ["ssh"], "hostname": "srv", "os": "Linux"})
            assert created is True
            assert db.add.called

    def test_existing_host(self):
        db = MagicMock()
        existing = MagicMock()
        existing.ports = [80]
        existing.services = ["http"]
        existing.hostname = ""
        existing.os = ""
        existing.import_source = ""
        db.query.return_value.filter.return_value.first.return_value = existing
        h, created = nmap_upsert_host(db, "p1", {"ip": "10.0.0.1", "ports": [22], "services": ["ssh"], "hostname": "srv", "os": "Linux"})
        assert created is False
        assert 22 in existing.ports
        assert existing.hostname == "srv"

    def test_existing_with_hostname(self):
        db = MagicMock()
        existing = MagicMock()
        existing.ports = []
        existing.services = []
        existing.hostname = "existing_name"
        existing.os = "Unknown"
        existing.import_source = "nmap"
        db.query.return_value.filter.return_value.first.return_value = existing
        h, created = nmap_upsert_host(db, "p1", {"ip": "10.0.0.1", "ports": [], "services": [], "hostname": "new", "os": "Win"})
        assert existing.hostname == "existing_name"


class TestCmeUpsertHost:
    def test_new_host(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        with patch("app.core.scan_helpers.new_id", return_value="h1"):
            h, created = cme_upsert_host(db, "p1", {"ip": "10.0.0.1", "ports": [445], "services": ["smb"], "hostname": "dc"})
            assert created is True

    def test_existing_host(self):
        db = MagicMock()
        existing = MagicMock()
        existing.ports = []
        existing.services = []
        existing.hostname = ""
        existing.import_source = ""
        db.query.return_value.filter.return_value.first.return_value = existing
        h, created = cme_upsert_host(db, "p1", {"ip": "10.0.0.1", "ports": [445], "services": ["smb"], "hostname": "dc"})
        assert created is False
        assert existing.hostname == "dc"


class TestCmeUpsertCred:
    def test_new(self):
        db = MagicMock()
        with patch("app.core.scan_helpers.new_id", return_value="crd1"):
            c, created = cme_upsert_cred(db, "p1", {"username": "admin", "secret": "pass"}, "corp", set())
            assert created is True
            assert db.add.called

    def test_duplicate(self):
        db = MagicMock()
        c, created = cme_upsert_cred(db, "p1", {"username": "admin", "service": "smb"}, "corp", {("admin", "smb")})
        assert created is False


class TestCmeBuildAuth:
    def test_hash(self):
        r = cme_build_auth({"hash": "abc123", "username": "admin"})
        assert "-H" in r
        assert "admin" in r

    def test_password(self):
        r = cme_build_auth({"username": "admin", "password": "pass"})
        assert "-p" in r

    def test_username_only(self):
        r = cme_build_auth({"username": "admin"})
        assert "-u" in r

    def test_empty(self):
        r = cme_build_auth({})
        assert r == ""


class TestCmeProcessHosts:
    def test_basic(self):
        db = MagicMock()
        with patch("app.core.scan_helpers.cme_upsert_host", return_value=(MagicMock(), True)):
            hosts, domains, created = cme_process_hosts(db, "p1", [{"ip": "10.0.0.1", "domain": "corp", "ports": [], "services": []}])
            assert created == 1
            assert domains["10.0.0.1"] == "corp"


class TestCmeProcessCreds:
    def test_basic(self):
        db = MagicMock()
        with patch("app.core.scan_helpers.cme_upsert_cred", return_value=(MagicMock(), True)):
            creds, created = cme_process_creds(db, "p1", [{"username": "admin"}], "corp", set())
            assert created == 1


class TestHttpxUpsertHost:
    def test_new_by_ip(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        with patch("app.core.scan_helpers.new_id", return_value="h1"):
            h = httpx_upsert_host(db, "p1", {"host": "10.0.0.1", "port": 443})
            assert db.add.called

    def test_existing(self):
        db = MagicMock()
        existing = MagicMock()
        existing.ports = [80]
        existing.services = ["http"]
        db.query.return_value.filter.return_value.first.return_value = existing
        h = httpx_upsert_host(db, "p1", {"host": "10.0.0.1", "port": 443})
        assert 443 in existing.ports

    def test_http_port(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        with patch("app.core.scan_helpers.new_id", return_value="h1"):
            h = httpx_upsert_host(db, "p1", {"host": "10.0.0.1", "port": 8080})
            assert db.add.called


class TestFfufSeverity:
    def test_200(self):
        assert ffuf_severity(200, "/foo") == "low"

    def test_204(self):
        assert ffuf_severity(204, "/foo") == "low"

    def test_admin_path(self):
        assert ffuf_severity(200, "/admin") == "medium"

    def test_config_path(self):
        assert ffuf_severity(403, "/.env") == "medium"

    def test_normal(self):
        assert ffuf_severity(403, "/foo") == "info"


class TestFfufUpsertFinding:
    def test_new(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        with patch("app.core.scan_helpers.new_id", return_value="f1"):
            r = ffuf_upsert_finding(db, "p1", {"status": 200, "url": "http://x/admin", "input": {}, "length": 100, "words": 50}, "http://x", "ts")
            assert r is True

    def test_existing(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = MagicMock()
        r = ffuf_upsert_finding(db, "p1", {"status": 200, "url": "http://x/admin", "input": {}}, "http://x", "ts")
        assert r is False


class TestDonpapiUpsertCred:
    def test_new(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        with patch("app.core.scan_helpers.new_id", return_value="c1"):
            r = donpapi_upsert_cred(db, "p1", {"username": "admin", "domain": "corp", "service": "smb", "secret": "pass"}, "10.0.0.1", lambda x: x)
            assert r is True

    def test_existing(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = MagicMock()
        r = donpapi_upsert_cred(db, "p1", {"username": "admin", "domain": "corp", "service": "smb", "secret": "pass"}, "10.0.0.1", lambda x: x)
        assert r is False


class TestDonpapiBuildFetchCmd:
    def test_basic(self):
        cmd = _donpapi_build_fetch_cmd("/tmp/output")
        assert "tar" in cmd
        assert "/tmp/output" in cmd
