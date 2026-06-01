"""Tests for C2 exec helper functions."""
import pytest
from unittest.mock import MagicMock

from app.routers.c2._exec import (
    _cred_matches_host,
    _render_command_with_cred,
    _build_host_action_session,
    _cred_matches_project_host,
    _build_rootnotes_cred_dict,
    SUPPORTED_EXEC_C2_TYPES,
)


class FakeHost:
    def __init__(self, **kw):
        self.ip = kw.get("ip", "")
        self.ips = kw.get("ips", [])
        self.hostname = kw.get("hostname", "")
        self.domain = kw.get("domain", "")
        self.id = kw.get("id", "h1")
        for k, v in kw.items():
            setattr(self, k, v)


class FakeCred:
    def __init__(self, **kw):
        self.id = kw.get("id", "cr1")
        self.username = kw.get("username", "")
        self.secret = kw.get("secret", "")
        self.domain = kw.get("domain", "")
        self.host = kw.get("host", "")
        self.type = kw.get("type", "plain")
        self.host_ids = kw.get("host_ids", [])
        self.is_domain = kw.get("is_domain", False)
        for k, v in kw.items():
            setattr(self, k, v)


class TestCredMatchesHost:
    def test_matches_by_ip(self):
        cred = {"host": "10.0.0.1"}
        host = FakeHost(ip="10.0.0.1")
        assert _cred_matches_host(cred, host) is True

    def test_matches_by_ips_list(self):
        cred = {"host": "10.0.0.2"}
        host = FakeHost(ip="10.0.0.1", ips=["10.0.0.2"])
        assert _cred_matches_host(cred, host) is True

    def test_matches_by_hostname(self):
        cred = {"host": "web01"}
        host = FakeHost(ip="10.0.0.1", hostname="web01")
        assert _cred_matches_host(cred, host) is True

    def test_matches_by_domain(self):
        cred = {"domain": "corp.local"}
        host = FakeHost(ip="10.0.0.1", domain="corp.local")
        assert _cred_matches_host(cred, host) is True

    def test_no_match(self):
        cred = {"host": "10.0.0.99", "domain": "other.local"}
        host = FakeHost(ip="10.0.0.1", hostname="pc1", domain="corp.local")
        assert _cred_matches_host(cred, host) is False

    def test_empty_cred_host(self):
        cred = {"host": ""}
        host = FakeHost(ip="10.0.0.1")
        assert _cred_matches_host(cred, host) is False

    def test_empty_domain_no_match(self):
        cred = {"domain": ""}
        host = FakeHost(domain="")
        assert _cred_matches_host(cred, host) is False


class TestRenderCommandWithCred:
    def test_no_cred(self):
        assert _render_command_with_cred("whoami", None, None) == "whoami"

    def test_user_placeholder(self):
        cred = {"username": "admin", "secret": "pass123", "domain": "CORP"}
        result = _render_command_with_cred("runas {{USER}} {{PASS}}", cred, None)
        assert "admin" in result
        assert "pass123" in result

    def test_all_placeholders(self):
        cred = {"username": "admin", "secret": "P@ss", "domain": "CORP"}
        host = FakeHost(ip="10.0.0.1")
        cmd = "{{USERNAME}}:{{PASSWORD}}:{{DOMAIN}}:{{HOST}}"
        result = _render_command_with_cred(cmd, cred, host)
        assert result == "admin:P@ss:CORP:10.0.0.1"

    def test_hash_placeholder(self):
        cred = {"secret": "abc123hash"}
        result = _render_command_with_cred("pth {{HASH}}", cred, None)
        assert "abc123hash" in result

    def test_realm_placeholder(self):
        cred = {"domain": "CORP.LOCAL"}
        result = _render_command_with_cred("kerb {{REALM}}", cred, None)
        assert "CORP.LOCAL" in result

    def test_target_placeholder(self):
        cred = {"username": "u", "secret": "s"}
        host = FakeHost(ip="192.168.1.1")
        result = _render_command_with_cred("attack {{TARGET}}", cred, host)
        assert "192.168.1.1" in result


class TestBuildHostActionSession:
    def test_basic(self):
        cfg = {"id": "c2_1", "type": "adaptix", "name": "My Adaptix"}
        agent = {"agent_id": "a1", "beacon_id": "b1", "ip": "10.0.0.1", "hostname": "pc1", "username": "admin", "alive": True, "mark": "alive", "last_seen": "2025-01-01"}
        result = _build_host_action_session(cfg, agent)
        assert result["integration_id"] == "c2_1"
        assert result["integration_type"] == "adaptix"
        assert result["agent_id"] == "a1"
        assert result["ip"] == "10.0.0.1"
        assert result["alive"] is True

    def test_name_fallback_to_type(self):
        cfg = {"id": "c2_1", "type": "sliver"}
        agent = {"beacon_id": "b2"}
        result = _build_host_action_session(cfg, agent)
        assert result["integration_name"] == "sliver"

    def test_agent_id_from_beacon(self):
        cfg = {"id": "c2", "type": "adaptix"}
        agent = {"beacon_id": "b3"}
        result = _build_host_action_session(cfg, agent)
        assert result["agent_id"] == "b3"

    def test_defaults(self):
        cfg = {"id": "c2", "type": "adaptix"}
        agent = {}
        result = _build_host_action_session(cfg, agent)
        assert result["alive"] is True
        assert result["ip"] == ""


class TestCredMatchesProjectHost:
    def test_matches_by_host_id(self):
        cred = FakeCred(host_ids=["h1"])
        host = FakeHost(id="h1")
        assert _cred_matches_project_host(cred, host) is True

    def test_matches_by_ip(self):
        cred = FakeCred(host="10.0.0.1")
        host = FakeHost(ip="10.0.0.1")
        assert _cred_matches_project_host(cred, host) is True

    def test_matches_by_hostname(self):
        cred = FakeCred(host="web01")
        host = FakeHost(hostname="web01")
        assert _cred_matches_project_host(cred, host) is True

    def test_matches_by_domain(self):
        cred = FakeCred(is_domain=True, domain="corp.local")
        host = FakeHost(domain="corp.local")
        assert _cred_matches_project_host(cred, host) is True

    def test_no_match(self):
        cred = FakeCred(host="10.0.0.99", host_ids=[])
        host = FakeHost(ip="10.0.0.1", hostname="pc1", domain="other.local")
        assert _cred_matches_project_host(cred, host) is False

    def test_empty_host_field(self):
        cred = FakeCred(host="", host_ids=[])
        host = FakeHost(ip="10.0.0.1")
        assert _cred_matches_project_host(cred, host) is False


class TestBuildRootnotesCredDict:
    def test_with_secret(self):
        cred = FakeCred(id="cr1", username="admin", secret="enc_pass", domain="CORP", host="10.0.0.1", type="plain")
        with pytest.MonkeyPatch.context() as m:
            m.setattr("app.routers.c2._exec.decrypt_str", lambda x: "decrypted_" + x)
            result = _build_rootnotes_cred_dict(cred, True)
        assert result["id"] == "cr1"
        assert result["source"] == "rootnotes"
        assert result["username"] == "admin"
        assert result["secret"].startswith("decrypted_")

    def test_without_secret(self):
        cred = FakeCred(id="cr2", username="user1")
        with pytest.MonkeyPatch.context() as m:
            m.setattr("app.routers.c2._exec.decrypt_str", lambda x: "dec")
            result = _build_rootnotes_cred_dict(cred, False)
        assert result["secret"] == ""


class TestSupportedTypes:
    def test_contains_expected(self):
        assert "adaptix" in SUPPORTED_EXEC_C2_TYPES
        assert "mythic" in SUPPORTED_EXEC_C2_TYPES
        assert "sliver" in SUPPORTED_EXEC_C2_TYPES
