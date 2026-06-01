import pytest
from unittest.mock import MagicMock, patch

from app.routers.c2._exec import (
    _cred_matches_host,
    _render_command_with_cred,
    _build_host_action_session,
    _cred_matches_project_host,
    _build_rootnotes_cred_dict,
    SUPPORTED_EXEC_C2_TYPES,
)


class TestCredMatchesHost:
    def test_ip_match(self):
        cred = {"host": "10.0.0.1"}
        host = MagicMock()
        host.ips = ["10.0.0.2"]
        host.ip = "10.0.0.1"
        host.hostname = "srv1"
        assert _cred_matches_host(cred, host) is True

    def test_ips_match(self):
        cred = {"host": "10.0.0.3"}
        host = MagicMock()
        host.ips = ["10.0.0.3"]
        host.ip = "10.0.0.1"
        assert _cred_matches_host(cred, host) is True

    def test_hostname_match(self):
        cred = {"host": "SRV1"}
        host = MagicMock()
        host.ips = []
        host.ip = "10.0.0.1"
        host.hostname = "SRV1"
        assert _cred_matches_host(cred, host) is True

    def test_domain_match(self):
        cred = {"domain": "corp.local"}
        host = MagicMock()
        host.ips = []
        host.ip = "10.0.0.1"
        host.hostname = ""
        host.domain = "corp.local"
        assert _cred_matches_host(cred, host) is True

    def test_no_match(self):
        cred = {"host": "10.0.0.99", "domain": ""}
        host = MagicMock()
        host.ips = []
        host.ip = "10.0.0.1"
        host.hostname = "srv1"
        host.domain = "other.local"
        assert _cred_matches_host(cred, host) is False


class TestRenderCommandWithCred:
    def test_no_cred(self):
        assert _render_command_with_cred("whoami", None, None) == "whoami"

    def test_substitutes(self):
        cred = {"username": "admin", "secret": "pass123", "domain": "corp"}
        host = MagicMock()
        host.ip = "10.0.0.1"
        result = _render_command_with_cred("{{USER}} {{PASS}} {{DOMAIN}} {{HOST}}", cred, host)
        assert "admin" in result
        assert "pass123" in result
        assert "corp" in result
        assert "10.0.0.1" in result

    def test_all_placeholders(self):
        cred = {"username": "u", "secret": "s", "domain": "d"}
        host = MagicMock()
        host.ip = "10.0.0.1"
        cmd = "{{USERNAME}} {{USER}} {{PASSWORD}} {{PASS}} {{SECRET}} {{HASH}} {{DOMAIN}} {{REALM}} {{HOST}} {{TARGET}}"
        result = _render_command_with_cred(cmd, cred, host)
        assert "u" in result
        assert "s" in result


class TestBuildHostActionSession:
    def test_basic(self):
        cfg = {"id": "c2_1", "name": "test", "type": "sliver"}
        agent = {"agent_id": "a1", "beacon_id": "b1", "ip": "10.0.0.1", "hostname": "SRV1", "username": "admin", "domain": "corp", "os": "Windows", "arch": "x64", "process": "implant", "listener": "l1", "session_type": "session", "alive": True, "mark": "alive", "last_seen": "2025-01-01"}
        result = _build_host_action_session(cfg, agent)
        assert result["integration_id"] == "c2_1"
        assert result["ip"] == "10.0.0.1"
        assert result["integration_type"] == "sliver"


class TestCredMatchesProjectHost:
    def test_host_ids_match(self):
        cred = MagicMock()
        cred.host_ids = ["h1"]
        cred.host = ""
        cred.is_domain = False
        host = MagicMock()
        host.id = "h1"
        assert _cred_matches_project_host(cred, host) is True

    def test_host_ip_match(self):
        cred = MagicMock()
        cred.host_ids = []
        cred.host = "10.0.0.1"
        cred.is_domain = False
        host = MagicMock()
        host.id = "h1"
        host.ip = "10.0.0.1"
        host.hostname = ""
        assert _cred_matches_project_host(cred, host) is True

    def test_domain_match(self):
        cred = MagicMock()
        cred.host_ids = []
        cred.host = ""
        cred.is_domain = True
        cred.domain = "corp.local"
        host = MagicMock()
        host.id = "h1"
        host.ip = "10.0.0.1"
        host.hostname = ""
        host.domain = "corp.local"
        assert _cred_matches_project_host(cred, host) is True


class TestBuildRootnotesCredDict:
    def test_with_secret(self):
        cred = MagicMock()
        cred.id = "cr1"
        cred.username = "admin"
        cred.secret = ""
        cred.domain = "corp"
        cred.host = "10.0.0.1"
        cred.type = "plain"
        with patch("app.routers.c2._exec.decrypt_str", return_value="pass"):
            result = _build_rootnotes_cred_dict(cred, True)
            assert result["secret"] == "pass"
            assert result["source"] == "rootnotes"

    def test_without_secret(self):
        cred = MagicMock()
        cred.id = "cr1"
        cred.username = "admin"
        cred.secret = ""
        cred.domain = ""
        cred.host = ""
        cred.type = "plain"
        result = _build_rootnotes_cred_dict(cred, False)
        assert result["secret"] == ""


class TestSupportedTypes:
    def test_contains_expected(self):
        assert "adaptix" in SUPPORTED_EXEC_C2_TYPES
        assert "mythic" in SUPPORTED_EXEC_C2_TYPES
        assert "sliver" in SUPPORTED_EXEC_C2_TYPES
