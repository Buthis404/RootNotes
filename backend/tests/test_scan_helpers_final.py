import pytest
from unittest.mock import MagicMock, patch

from app.core.scan_helpers import (
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


class TestCmeUpsertHost:
    def test_existing(self):
        db = MagicMock()
        existing = MagicMock()
        existing.hostname = ""
        existing.ports = ["22/tcp"]
        existing.services = ["ssh"]
        existing.import_source = ""
        db.query.return_value.filter.return_value.first.return_value = existing
        host, created = cme_upsert_host(db, "p1", {"ip": "10.0.0.1", "hostname": "SRV1", "ports": ["445/tcp"], "services": ["smb"]})
        assert created is False
        assert existing.hostname == "SRV1"

    def test_new(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        host, created = cme_upsert_host(db, "p1", {"ip": "10.0.0.1", "hostname": "", "ports": [], "services": []})
        assert created is True


class TestCmeUpsertCred:
    def test_existing_key(self):
        db = MagicMock()
        result = cme_upsert_cred(db, "p1", {"username": "admin", "service": "smb"}, "corp", {("admin", "smb")})
        assert result[0] is None

    def test_new(self):
        db = MagicMock()
        result = cme_upsert_cred(db, "p1", {"username": "admin", "secret": "pass", "type": "plain", "service": "smb"}, "corp", set())
        assert result[0] is not None
        assert result[1] is True


class TestCmeBuildAuth:
    def test_hash(self):
        result = cme_build_auth({"hash": "AADM123", "username": "admin"})
        assert "-H" in result

    def test_user_pass(self):
        result = cme_build_auth({"username": "admin", "password": "pass"})
        assert "-u" in result
        assert "-p" in result

    def test_user_only(self):
        result = cme_build_auth({"username": "admin"})
        assert "-u" in result

    def test_empty(self):
        assert cme_build_auth({}) == ""


class TestCmeProcessHosts:
    def test_process(self):
        db = MagicMock()
        with patch("app.core.scan_helpers.cme_upsert_host", return_value=(MagicMock(), True)):
            hosts, domains, created = cme_process_hosts(db, "p1", [{"ip": "10.0.0.1", "domain": "corp"}])
            assert created == 1
            assert "10.0.0.1" in domains


class TestCmeProcessCreds:
    def test_process(self):
        db = MagicMock()
        with patch("app.core.scan_helpers.cme_upsert_cred", return_value=(MagicMock(), True)):
            creds, created = cme_process_creds(db, "p1", [{"username": "admin"}], "corp", set())
            assert created == 1


class TestHttpxUpsertHost:
    def test_new(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        host = httpx_upsert_host(db, "p1", {"host": "10.0.0.1", "port": "443/tcp"})
        assert host is not None

    def test_existing_by_ip(self):
        db = MagicMock()
        existing = MagicMock()
        existing.ports = []
        existing.services = []
        db.query.return_value.filter.return_value.first.return_value = existing
        host = httpx_upsert_host(db, "p1", {"host": "10.0.0.1", "port": "80/tcp"})
        assert host == existing

    def test_existing_by_hostname(self):
        db = MagicMock()
        existing = MagicMock()
        existing.ports = []
        existing.services = []
        db.query.return_value.filter.return_value.first.side_effect = [None, existing]
        host = httpx_upsert_host(db, "p1", {"host": "srv1.example.com", "port": "443/tcp"})
        assert host == existing


class TestFfufSeverity:
    def test_200(self):
        assert ffuf_severity(200, "/path") == "low"

    def test_204(self):
        assert ffuf_severity(204, "/path") == "low"

    def test_sensitive_path(self):
        assert ffuf_severity(200, "/admin") == "medium"

    def test_env_path(self):
        assert ffuf_severity(200, "/.env") == "medium"

    def test_default(self):
        assert ffuf_severity(403, "/normal") == "info"


class TestFfufUpsertFinding:
    def test_existing(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = MagicMock()
        assert ffuf_upsert_finding(db, "p1", {"status": 200, "input": {"FUZZ": "/admin"}, "url": "http://x/admin"}, "http://x", "ts") is False

    def test_new(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        assert ffuf_upsert_finding(db, "p1", {"status": 200, "input": {"FUZZ": "/admin"}, "url": "http://x/admin", "length": 100, "words": 50}, "http://x", "ts") is True


class TestDonpapiUpsertCred:
    def test_existing(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = MagicMock()
        assert donpapi_upsert_cred(db, "p1", {"username": "admin", "domain": "", "service": "smb", "secret": "x", "kind": "dpapi"}, "10.0.0.1", lambda x: x) is False

    def test_new(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        assert donpapi_upsert_cred(db, "p1", {"username": "admin", "domain": "", "service": "smb", "secret": "x", "kind": "dpapi", "host_hint": "10.0.0.1"}, "10.0.0.1", lambda x: x) is True


class TestDonpapiBuildFetchCmd:
    def test_basic(self):
        result = _donpapi_build_fetch_cmd("/tmp/output")
        assert "tar" in result
        assert "base64" in result
