import pytest
from unittest.mock import MagicMock, patch

from app.routers.c2._exec import (
    _cred_matches_host,
    _render_command_with_cred,
    _build_host_action_session,
    _cred_matches_project_host,
    _build_rootnotes_cred_dict,
)


class TestCredMatchesHost:
    def test_ip_match(self):
        cred = {"host": "10.0.0.1"}
        host = MagicMock()
        host.ips = []
        host.ip = "10.0.0.1"
        host.hostname = ""
        host.domain = ""
        assert _cred_matches_host(cred, host) is True

    def test_ips_match(self):
        cred = {"host": "10.0.0.2"}
        host = MagicMock()
        host.ips = ["10.0.0.1", "10.0.0.2"]
        host.ip = "10.0.0.1"
        host.hostname = ""
        host.domain = ""
        assert _cred_matches_host(cred, host) is True

    def test_hostname_match(self):
        cred = {"host": "srv01"}
        host = MagicMock()
        host.ips = []
        host.ip = "10.0.0.1"
        host.hostname = "srv01"
        host.domain = ""
        assert _cred_matches_host(cred, host) is True

    def test_domain_match(self):
        cred = {"host": "", "domain": "corp.local"}
        host = MagicMock()
        host.ips = []
        host.ip = "10.0.0.1"
        host.hostname = ""
        host.domain = "corp.local"
        assert _cred_matches_host(cred, host) is True

    def test_no_match(self):
        cred = {"host": "other", "domain": ""}
        host = MagicMock()
        host.ips = []
        host.ip = "10.0.0.1"
        host.hostname = "srv01"
        host.domain = ""
        assert _cred_matches_host(cred, host) is False


class TestRenderCommandWithCred:
    def test_no_cred(self):
        assert _render_command_with_cred("cmd", None, None) == "cmd"

    def test_substitutions(self):
        cred = {"username": "admin", "secret": "pass123", "domain": "corp"}
        host = MagicMock()
        host.ip = "10.0.0.1"
        result = _render_command_with_cred("{{USER}} {{PASS}} {{DOMAIN}} {{HOST}}", cred, host)
        assert "admin" in result
        assert "pass123" in result
        assert "corp" in result
        assert "10.0.0.1" in result

    def test_all_tokens(self):
        cred = {"username": "u", "secret": "s", "domain": "d"}
        host = MagicMock()
        host.ip = "1.1.1.1"
        result = _render_command_with_cred(
            "{{USERNAME}} {{USER}} {{PASSWORD}} {{PASS}} {{SECRET}} {{HASH}} {{DOMAIN}} {{REALM}} {{HOST}} {{TARGET}}",
            cred, host)
        assert "u" in result
        assert "s" in result
        assert "d" in result


class TestBuildHostActionSession:
    def test_basic(self):
        cfg = {"id": "c2_1", "name": "test", "type": "adaptix"}
        agent = {"agent_id": "a1", "beacon_id": "b1", "ip": "10.0.0.1",
                 "hostname": "srv", "username": "admin", "domain": "corp",
                 "os": "Win", "arch": "x64", "process": "p", "listener": "l",
                 "session_type": "session", "alive": True, "mark": "active",
                 "last_seen": "now"}
        r = _build_host_action_session(cfg, agent)
        assert r["integration_id"] == "c2_1"
        assert r["ip"] == "10.0.0.1"
        assert r["alive"] is True

    def test_missing_fields(self):
        cfg = {"id": "c2_1", "type": "sliver"}
        r = _build_host_action_session(cfg, {})
        assert r["ip"] == ""
        assert r["alive"] is True


class TestCredMatchesProjectHost:
    def test_host_id_match(self):
        cred = MagicMock()
        cred.host_ids = ["h1"]
        cred.host = ""
        cred.is_domain = False
        cred.domain = ""
        host = MagicMock()
        host.id = "h1"
        host.ip = "10.0.0.1"
        host.hostname = "srv"
        host.domain = ""
        assert _cred_matches_project_host(cred, host) is True

    def test_ip_match(self):
        cred = MagicMock()
        cred.host_ids = []
        cred.host = "10.0.0.1"
        cred.is_domain = False
        cred.domain = ""
        host = MagicMock()
        host.id = "h2"
        host.ip = "10.0.0.1"
        host.hostname = "srv"
        host.domain = ""
        assert _cred_matches_project_host(cred, host) is True

    def test_domain_match(self):
        cred = MagicMock()
        cred.host_ids = []
        cred.host = ""
        cred.is_domain = True
        cred.domain = "corp.local"
        host = MagicMock()
        host.id = "h2"
        host.ip = "10.0.0.1"
        host.hostname = "srv"
        host.domain = "corp.local"
        assert _cred_matches_project_host(cred, host) is True

    def test_no_match(self):
        cred = MagicMock()
        cred.host_ids = []
        cred.host = ""
        cred.is_domain = False
        cred.domain = ""
        host = MagicMock()
        host.id = "h2"
        host.ip = "10.0.0.1"
        host.hostname = "srv"
        host.domain = ""
        assert _cred_matches_project_host(cred, host) is False


class TestBuildRootnotesCredDict:
    def test_with_secret(self):
        cred = MagicMock()
        cred.id = "crd1"
        cred.username = "admin"
        cred.secret = "enc:pass"
        cred.domain = "corp"
        cred.host = "10.0.0.1"
        cred.type = "plain"
        with patch("app.routers.c2._exec.decrypt_str", return_value="pass123"):
            r = _build_rootnotes_cred_dict(cred, True)
            assert r["secret"] == "pass123"
            assert r["source"] == "rootnotes"

    def test_no_secret(self):
        cred = MagicMock()
        cred.id = "crd1"
        cred.username = "admin"
        cred.secret = ""
        cred.domain = ""
        cred.host = ""
        cred.type = "plain"
        with patch("app.routers.c2._exec.decrypt_str", return_value=""):
            r = _build_rootnotes_cred_dict(cred, False)
            assert r["secret"] == ""
