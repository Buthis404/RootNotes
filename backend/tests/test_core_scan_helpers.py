"""Extended tests for scan_helpers — donpapi and httpx helpers."""
import pytest
from unittest.mock import MagicMock, patch

from app.core.scan_helpers import (
    httpx_upsert_host,
    ffuf_severity,
    ffuf_upsert_finding,
    cme_build_auth,
    donpapi_upsert_cred,
    _donpapi_build_fetch_cmd,
)


class TestHttpxUpsertHost:
    def test_new_host(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        r = {"host": "10.0.0.1", "port": 443}
        result = httpx_upsert_host(db, "p1", r)
        assert result.ip == "10.0.0.1"
        db.add.assert_called()

    def test_existing_by_ip(self):
        existing = MagicMock()
        existing.ports = []
        existing.services = []
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = existing
        r = {"host": "10.0.0.1", "port": 443}
        result = httpx_upsert_host(db, "p1", r)
        assert result is existing

    def test_existing_by_hostname(self):
        existing = MagicMock()
        existing.ports = []
        existing.services = []
        db = MagicMock()
        db.query.return_value.filter.return_value.first.side_effect = [None, existing]
        r = {"host": "web01", "port": 80}
        result = httpx_upsert_host(db, "p1", r)
        assert result is existing


class TestFfufSeverity:
    def test_200_low(self):
        assert ffuf_severity(200, "/page") == "low"

    def test_204_low(self):
        assert ffuf_severity(204, "/page") == "low"

    def test_admin_medium(self):
        assert ffuf_severity(403, "/admin") == "medium"

    def test_env_medium(self):
        assert ffuf_severity(200, "/.env") == "medium"

    def test_default_info(self):
        assert ffuf_severity(404, "/page") == "info"

    def test_secret_medium(self):
        assert ffuf_severity(200, "/secret") == "medium"

    def test_backup_medium(self):
        assert ffuf_severity(200, "/backup.sql") == "medium"

    def test_passwd_medium(self):
        assert ffuf_severity(200, "/etc/passwd") == "medium"

    def test_config_medium(self):
        assert ffuf_severity(200, "/config.yml") == "medium"


class TestFfufUpsertFinding:
    def test_new_finding(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        r = {"status": 200, "input": {"FUZZ": "/admin"}, "url": "http://x/admin", "length": 100, "words": 50}
        result = ffuf_upsert_finding(db, "p1", r, "http://x", "2025-01-01")
        assert result is True
        db.add.assert_called()

    def test_existing_finding(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = MagicMock()
        result = ffuf_upsert_finding(db, "p1", {"status": 200, "url": "http://x/a"}, "http://x", "ts")
        assert result is False


class TestCmeBuildAuth:
    def test_with_hash(self):
        result = cme_build_auth({"hash": "nthash", "username": "admin"})
        assert "-H 'nthash'" in result

    def test_with_password(self):
        result = cme_build_auth({"username": "admin", "password": "pass"})
        assert "-u 'admin'" in result
        assert "-p 'pass'" in result

    def test_username_only(self):
        result = cme_build_auth({"username": "admin"})
        assert "-u 'admin'" in result

    def test_empty(self):
        assert cme_build_auth({}) == ""


class TestDonpapiUpsertCred:
    def test_new_cred(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        encrypt_fn = lambda x: f"enc_{x}"
        cred = {"username": "admin", "secret": "pass", "service": "smb",
                "domain": "dom", "host_hint": "10.0.0.1", "kind": "dpapi"}
        result = donpapi_upsert_cred(db, "p1", cred, "10.0.0.1", encrypt_fn)
        assert result is True

    def test_existing_cred(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = MagicMock()
        result = donpapi_upsert_cred(db, "p1", {"username": "a", "secret": "s",
                                                  "service": "smb"}, "t", lambda x: x)
        assert result is False


class TestDonpapiBuildFetchCmd:
    def test_basic(self):
        cmd = _donpapi_build_fetch_cmd("/tmp/output")
        assert "tar" in cmd
        assert "/tmp/output" in cmd
        assert "base64" in cmd
