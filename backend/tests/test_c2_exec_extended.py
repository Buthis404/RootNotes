"""Extended tests for app.routers.c2._exec — helper functions."""
import pytest
from unittest.mock import MagicMock

from app.routers.c2._exec import (
    _cred_matches_host,
    _render_command_with_cred,
    _build_host_action_session,
    _cred_matches_project_host,
    _build_rootnotes_cred_dict,
)


class TestCredMatchesHost:
    def test_ip_match(self):
        host = MagicMock()
        host.ips = ["10.0.0.1"]
        host.ip = "10.0.0.1"
        host.hostname = "pc1"
        host.domain = ""
        assert _cred_matches_host({"host": "10.0.0.1"}, host) is True

    def test_hostname_match(self):
        host = MagicMock()
        host.ips = []
        host.ip = ""
        host.hostname = "pc1"
        host.domain = ""
        assert _cred_matches_host({"host": "pc1"}, host) is True

    def test_domain_match(self):
        host = MagicMock()
        host.ips = []
        host.ip = ""
        host.hostname = ""
        host.domain = "dom.local"
        assert _cred_matches_host({"domain": "dom.local"}, host) is True

    def test_no_match(self):
        host = MagicMock()
        host.ips = []
        host.ip = "10.0.0.1"
        host.hostname = "pc1"
        host.domain = "other.local"
        assert _cred_matches_host({"host": "10.0.0.2", "domain": "dom.local"}, host) is False


class TestRenderCommandWithCred:
    def test_no_cred(self):
        assert _render_command_with_cred("whoami", None, None) == "whoami"

    def test_replaces_placeholders(self):
        cred = {"username": "admin", "secret": "pass", "domain": "DOM"}
        host = MagicMock()
        host.ip = "10.0.0.1"
        result = _render_command_with_cred("{{USER}}:{{PASS}}@{{HOST}}", cred, host)
        assert "admin" in result
        assert "pass" in result
        assert "10.0.0.1" in result

    def test_all_placeholders(self):
        cred = {"username": "u", "secret": "s", "domain": "d"}
        host = MagicMock()
        host.ip = "1.1.1.1"
        cmd = "{{USERNAME}} {{USER}} {{PASS}} {{PASSWORD}} {{SECRET}} {{HASH}} {{DOMAIN}} {{REALM}} {{HOST}} {{TARGET}}"
        result = _render_command_with_cred(cmd, cred, host)
        assert "u" in result
        assert "s" in result
        assert "d" in result


class TestBuildHostActionSession:
    def test_basic(self):
        cfg = {"id": "c2-1", "name": "test", "type": "adaptix"}
        agent = {
            "agent_id": "a1", "beacon_id": "b1", "ip": "10.0.0.1",
            "hostname": "pc", "username": "u", "domain": "d", "os": "Win",
            "arch": "x64", "process": "implant", "listener": "tcp",
            "session_type": "beacon", "alive": True, "mark": "alive",
            "last_seen": "2025-01-01",
        }
        result = _build_host_action_session(cfg, agent)
        assert result["integration_id"] == "c2-1"
        assert result["ip"] == "10.0.0.1"
        assert result["alive"] is True


class TestCredMatchesProjectHost:
    def test_host_id_match(self):
        cred = MagicMock()
        cred.host_ids = ["h1"]
        cred.host = ""
        cred.is_domain = False
        cred.domain = ""
        host = MagicMock()
        host.id = "h1"
        host.ip = ""
        host.hostname = ""
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
        host.hostname = "10.0.0.1"
        host.domain = ""
        assert _cred_matches_project_host(cred, host) is True

    def test_domain_match(self):
        cred = MagicMock()
        cred.host_ids = []
        cred.host = ""
        cred.is_domain = True
        cred.domain = "dom.local"
        host = MagicMock()
        host.id = "h3"
        host.ip = ""
        host.hostname = ""
        host.domain = "dom.local"
        assert _cred_matches_project_host(cred, host) is True

    def test_no_match(self):
        cred = MagicMock()
        cred.host_ids = []
        cred.host = "10.0.0.2"
        cred.is_domain = False
        cred.domain = ""
        host = MagicMock()
        host.id = "h4"
        host.ip = "10.0.0.1"
        host.hostname = "pc"
        host.domain = ""
        assert _cred_matches_project_host(cred, host) is False


class TestBuildRootnotesCredDict:
    def test_with_secret(self):
        cred = MagicMock()
        cred.id = "crd1"
        cred.username = "admin"
        cred.secret = ""
        cred.domain = "dom"
        cred.host = "10.0.0.1"
        cred.type = "plain"
        result = _build_rootnotes_cred_dict(cred, True)
        assert result["source"] == "rootnotes"
        assert result["username"] == "admin"

    def test_without_secret(self):
        cred = MagicMock()
        cred.id = "crd2"
        cred.username = "user"
        cred.secret = ""
        cred.domain = ""
        cred.host = ""
        cred.type = "key"
        result = _build_rootnotes_cred_dict(cred, False)
        assert result["secret"] == ""
