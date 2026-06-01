"""Consolidated tests for test_scan_helpers (merged variant files)."""

# ════════ from test_scan_helpers_final.py ════════
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


class TestCmeUpsertHost_final:
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


class TestCmeUpsertCred_final:
    def test_existing_key(self):
        db = MagicMock()
        result = cme_upsert_cred(db, "p1", {"username": "admin", "service": "smb"}, "corp", {("admin", "smb")})
        assert result[0] is None

    def test_new(self):
        db = MagicMock()
        result = cme_upsert_cred(db, "p1", {"username": "admin", "secret": "pass", "type": "plain", "service": "smb"}, "corp", set())
        assert result[0] is not None
        assert result[1] is True


class TestCmeBuildAuth_final:
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


class TestCmeProcessHosts_final:
    def test_process(self):
        db = MagicMock()
        with patch("app.core.scan_helpers.cme_upsert_host", return_value=(MagicMock(), True)):
            hosts, domains, created = cme_process_hosts(db, "p1", [{"ip": "10.0.0.1", "domain": "corp"}])
            assert created == 1
            assert "10.0.0.1" in domains


class TestCmeProcessCreds_final:
    def test_process(self):
        db = MagicMock()
        with patch("app.core.scan_helpers.cme_upsert_cred", return_value=(MagicMock(), True)):
            creds, created = cme_process_creds(db, "p1", [{"username": "admin"}], "corp", set())
            assert created == 1


class TestHttpxUpsertHost_final:
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


class TestFfufSeverity_final:
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


class TestFfufUpsertFinding_final:
    def test_existing(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = MagicMock()
        assert ffuf_upsert_finding(db, "p1", {"status": 200, "input": {"FUZZ": "/admin"}, "url": "http://x/admin"}, "http://x", "ts") is False

    def test_new(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        assert ffuf_upsert_finding(db, "p1", {"status": 200, "input": {"FUZZ": "/admin"}, "url": "http://x/admin", "length": 100, "words": 50}, "http://x", "ts") is True


class TestDonpapiUpsertCred_final:
    def test_existing(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = MagicMock()
        assert donpapi_upsert_cred(db, "p1", {"username": "admin", "domain": "", "service": "smb", "secret": "x", "kind": "dpapi"}, "10.0.0.1", lambda x: x) is False

    def test_new(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        assert donpapi_upsert_cred(db, "p1", {"username": "admin", "domain": "", "service": "smb", "secret": "x", "kind": "dpapi", "host_hint": "10.0.0.1"}, "10.0.0.1", lambda x: x) is True


class TestDonpapiBuildFetchCmd_final:
    def test_basic(self):
        result = _donpapi_build_fetch_cmd("/tmp/output")
        assert "tar" in result
        assert "base64" in result


# ════════ from test_scan_helpers_final2.py ════════
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


class TestNmapUpsertHost_final2:
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


class TestCmeUpsertHost_final2:
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


class TestCmeUpsertCred_final2:
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


class TestCmeBuildAuth_final2:
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


class TestCmeProcessHosts_final2:
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


class TestCmeProcessCreds_final2:
    def test_basic(self):
        db = MagicMock()
        creds = [{"username": "admin", "secret": "pass"}]
        objs, created = cme_process_creds(db, "p1", creds, "corp", set())
        assert created == 1


class TestHttpxUpsertHost_final2:
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


class TestFfufSeverity_final2:
    def test_200(self):
        assert ffuf_severity(200, "") == "low"

    def test_404(self):
        assert ffuf_severity(404, "") == "info"

    def test_sensitive_path(self):
        assert ffuf_severity(200, "/admin") == "medium"
        assert ffuf_severity(200, "/.env") == "medium"

    def test_normal_path(self):
        assert ffuf_severity(200, "/page") == "low"


class TestFfufUpsertFinding_final2:
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


class TestDonpapiUpsertCred_final2:
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


class TestDonpapiBuildFetchCmd_final2:
    def test_basic(self):
        r = _donpapi_build_fetch_cmd("/tmp/output")
        assert "tar" in r
        assert "/tmp/output" in r


# ════════ from test_scan_helpers_v3.py ════════
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


class TestNmapUpsertHost_v3:
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


class TestCmeUpsertHost_v3:
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


class TestCmeUpsertCred_v3:
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


class TestCmeBuildAuth_v3:
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


class TestCmeProcessHosts_v3:
    def test_basic(self):
        db = MagicMock()
        with patch("app.core.scan_helpers.cme_upsert_host", return_value=(MagicMock(), True)):
            hosts, domains, created = cme_process_hosts(db, "p1", [{"ip": "10.0.0.1", "domain": "corp", "ports": [], "services": []}])
            assert created == 1
            assert domains["10.0.0.1"] == "corp"


class TestCmeProcessCreds_v3:
    def test_basic(self):
        db = MagicMock()
        with patch("app.core.scan_helpers.cme_upsert_cred", return_value=(MagicMock(), True)):
            creds, created = cme_process_creds(db, "p1", [{"username": "admin"}], "corp", set())
            assert created == 1


class TestHttpxUpsertHost_v3:
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


class TestFfufSeverity_v3:
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


class TestFfufUpsertFinding_v3:
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


class TestDonpapiUpsertCred_v3:
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


class TestDonpapiBuildFetchCmd_v3:
    def test_basic(self):
        cmd = _donpapi_build_fetch_cmd("/tmp/output")
        assert "tar" in cmd
        assert "/tmp/output" in cmd
