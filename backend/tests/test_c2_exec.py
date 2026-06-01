"""Consolidated tests for test_c2_exec (merged variant files)."""

# ════════ from test_c2_exec_api.py ════════
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


class TestCredMatchesHost_api:
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


class TestRenderCommandWithCred_api:
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


class TestBuildHostActionSession_api:
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


class TestCredMatchesProjectHost_api:
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


class TestBuildRootnotesCredDict_api:
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


class TestSupportedTypes_api:
    def test_contains_expected(self):
        assert "adaptix" in SUPPORTED_EXEC_C2_TYPES
        assert "mythic" in SUPPORTED_EXEC_C2_TYPES
        assert "sliver" in SUPPORTED_EXEC_C2_TYPES


# ════════ from test_c2_exec_extended.py ════════
import pytest
from unittest.mock import MagicMock

from app.routers.c2._exec import (
    _cred_matches_host,
    _render_command_with_cred,
    _build_host_action_session,
    _cred_matches_project_host,
    _build_rootnotes_cred_dict,
)


class TestCredMatchesHost_extended:
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


class TestRenderCommandWithCred_extended:
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


class TestBuildHostActionSession_extended:
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


class TestCredMatchesProjectHost_extended:
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


class TestBuildRootnotesCredDict_extended:
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


# ════════ from test_c2_exec_final.py ════════
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


class TestCredMatchesHost_final:
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


class TestRenderCommandWithCred_final:
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


class TestBuildHostActionSession_final:
    def test_basic(self):
        cfg = {"id": "c2_1", "name": "test", "type": "sliver"}
        agent = {"agent_id": "a1", "beacon_id": "b1", "ip": "10.0.0.1", "hostname": "SRV1", "username": "admin", "domain": "corp", "os": "Windows", "arch": "x64", "process": "implant", "listener": "l1", "session_type": "session", "alive": True, "mark": "alive", "last_seen": "2025-01-01"}
        result = _build_host_action_session(cfg, agent)
        assert result["integration_id"] == "c2_1"
        assert result["ip"] == "10.0.0.1"
        assert result["integration_type"] == "sliver"


class TestCredMatchesProjectHost_final:
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


class TestBuildRootnotesCredDict_final:
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


class TestSupportedTypes_final:
    def test_contains_expected(self):
        assert "adaptix" in SUPPORTED_EXEC_C2_TYPES
        assert "mythic" in SUPPORTED_EXEC_C2_TYPES
        assert "sliver" in SUPPORTED_EXEC_C2_TYPES


# ════════ from test_c2_exec_final2.py ════════
import pytest
from unittest.mock import MagicMock, patch

from app.routers.c2._exec import (
    _cred_matches_host,
    _render_command_with_cred,
    _build_host_action_session,
    _cred_matches_project_host,
    _build_rootnotes_cred_dict,
)


class TestCredMatchesHost_final2:
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


class TestRenderCommandWithCred_final2:
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


class TestBuildHostActionSession_final2:
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


class TestCredMatchesProjectHost_final2:
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


class TestBuildRootnotesCredDict_final2:
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


# ════════ from test_c2_exec_v3.py ════════
import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from fastapi import HTTPException

from app.routers.c2._exec import (
    _cred_matches_host,
    _cred_matches_project_host,
    _build_rootnotes_cred_dict,
    _build_host_action_session,
    _process_integration_for_host,
    perform_c2_command,
    resolve_c2_cred,
    SUPPORTED_EXEC_C2_TYPES,
)


class TestProcessIntegrationForHost:
    @pytest.mark.asyncio
    async def test_unsupported_type(self):
        with patch("app.routers.c2._exec._LIVE_CONNECTORS", {}):
            await _process_integration_for_host(
                {"type": "unknown"}, set(), [], [], {}, "h1"
            )

    @pytest.mark.asyncio
    async def test_no_live_fn(self):
        with patch("app.routers.c2._exec.SUPPORTED_EXEC_C2_TYPES", {"sliver"}):
            with patch("app.routers.c2._exec._LIVE_CONNECTORS", {"sliver": None}):
                await _process_integration_for_host(
                    {"type": "sliver"}, set(), [], [], {}, "h1"
                )

    @pytest.mark.asyncio
    async def test_sliver_live(self):
        agent = {"ip": "10.0.0.1", "agent_id": "a1", "beacon_id": "", "hostname": "srv",
                 "username": "admin", "domain": "", "os": "Linux", "arch": "x64",
                 "process": "p", "listener": "l", "session_type": "session",
                 "alive": True, "mark": "alive", "last_seen": "now"}
        sessions = []
        c2_creds = []
        bof_catalog = {}
        mock_live = AsyncMock(return_value=[agent])
        with patch("app.routers.c2._exec.SUPPORTED_EXEC_C2_TYPES", {"sliver"}):
            with patch("app.routers.c2._exec._LIVE_CONNECTORS", {"sliver": mock_live}):
                await _process_integration_for_host(
                    {"type": "sliver", "id": "c1"}, {"10.0.0.1"},
                    sessions, c2_creds, bof_catalog, "h1"
                )
                assert len(sessions) == 1

    @pytest.mark.asyncio
    async def test_adaptix_with_creds_and_bof(self):
        sessions = []
        c2_creds = []
        bof_catalog = {}
        mock_live = AsyncMock(return_value=[{"ip": "10.0.0.1"}])
        mock_creds = AsyncMock(return_value=[{"c_creds_id": "cr1"}])
        mock_bof = AsyncMock(return_value=[{"name": "bof1"}])
        with patch("app.routers.c2._exec.SUPPORTED_EXEC_C2_TYPES", {"adaptix"}):
            with patch("app.routers.c2._exec._LIVE_CONNECTORS", {"adaptix": mock_live}):
                with patch("app.routers.c2._exec._adaptix_fetch_creds", mock_creds):
                    with patch("app.routers.c2._exec._adaptix_fetch_bof_catalog", mock_bof):
                        await _process_integration_for_host(
                            {"type": "adaptix", "id": "c1"}, {"10.0.0.1"},
                            sessions, c2_creds, bof_catalog, "h1"
                        )
                        assert len(c2_creds) == 1
                        assert "c1" in bof_catalog

    @pytest.mark.asyncio
    async def test_exception_logged(self):
        mock_live = AsyncMock(side_effect=Exception("conn refused"))
        with patch("app.routers.c2._exec.SUPPORTED_EXEC_C2_TYPES", {"sliver"}):
            with patch("app.routers.c2._exec._LIVE_CONNECTORS", {"sliver": mock_live}):
                await _process_integration_for_host(
                    {"type": "sliver", "id": "c1"}, {"10.0.0.1"},
                    [], [], {}, "h1"
                )

    @pytest.mark.asyncio
    async def test_adaptix_creds_fail(self):
        mock_live = AsyncMock(return_value=[])
        sessions = []
        c2_creds = []
        bof_catalog = {}
        with patch("app.routers.c2._exec.SUPPORTED_EXEC_C2_TYPES", {"adaptix"}):
            with patch("app.routers.c2._exec._LIVE_CONNECTORS", {"adaptix": mock_live}):
                with patch("app.routers.c2._exec._adaptix_fetch_creds",
                           side_effect=Exception("fail")):
                    with patch("app.routers.c2._exec._adaptix_fetch_bof_catalog",
                               return_value=[]):
                        await _process_integration_for_host(
                            {"type": "adaptix", "id": "c1"}, set(),
                            sessions, c2_creds, bof_catalog, "h1"
                        )


class TestPerformC2Command:
    @pytest.mark.asyncio
    async def test_unsupported_type(self):
        with pytest.raises(ValueError, match="not supported"):
            await perform_c2_command(
                MagicMock(), "p1", MagicMock(), {"type": "bad"},
                "a1", "cmd", "command", None, True, 12, "test"
            )

    @pytest.mark.asyncio
    async def test_mythic_exec(self):
        db = MagicMock()
        host = MagicMock()
        host.id = "h1"
        host.ip = "10.0.0.1"
        host.hostname = "srv"
        with patch("app.routers.c2._exec._mythic_execute", new_callable=AsyncMock,
                    return_value={"output": "root"}):
            with patch("app.routers.c2._exec.new_id", return_value="ha1"):
                with patch("app.routers.c2._exec.ts_now", return_value="ts"):
                    with patch("app.core.secret_scrub.scrub_for_cred", side_effect=lambda x, y: x):
                        with patch("app.routers.c2._exec.bcast"):
                            with patch("app.routers.c2._exec.log_event"):
                                result, activity, rendered = await perform_c2_command(
                                    db, "p1", host, {"type": "mythic", "id": "c1"},
                                    "a1", "whoami", "command", None, True, 12, "test exec"
                                )
                                assert result["output"] == "root"
                                assert db.add.called

    @pytest.mark.asyncio
    async def test_sliver_exec(self):
        db = MagicMock()
        host = MagicMock()
        host.id = "h1"
        host.ip = "10.0.0.1"
        host.hostname = "srv"
        with patch("app.routers.c2._exec._sliver_execute", new_callable=AsyncMock,
                    return_value={"output": "admin", "kind": "session"}):
            with patch("app.routers.c2._exec.new_id", return_value="ha1"):
                with patch("app.routers.c2._exec.ts_now", return_value="ts"):
                    with patch("app.core.secret_scrub.scrub_for_cred", side_effect=lambda x, y: x):
                        with patch("app.routers.c2._exec.bcast"):
                            with patch("app.routers.c2._exec.log_event"):
                                result, activity, rendered = await perform_c2_command(
                                    db, "p1", host, {"type": "sliver", "id": "c1"},
                                    "a1", "id", "command", None, True, 12, "test"
                                )
                                assert result["output"] == "admin"

    @pytest.mark.asyncio
    async def test_adaptix_exec(self):
        db = MagicMock()
        host = MagicMock()
        host.id = "h1"
        host.ip = "10.0.0.1"
        host.hostname = "srv"
        with patch("app.routers.c2._exec._adaptix_execute", new_callable=AsyncMock,
                    return_value={"output": "result", "message": ""}):
            with patch("app.routers.c2._exec.new_id", return_value="ha1"):
                with patch("app.routers.c2._exec.ts_now", return_value="ts"):
                    with patch("app.core.secret_scrub.scrub_for_cred", side_effect=lambda x, y: x):
                        with patch("app.routers.c2._exec.bcast"):
                            with patch("app.routers.c2._exec.log_event"):
                                result, activity, rendered = await perform_c2_command(
                                    db, "p1", host, {"type": "adaptix", "id": "c1"},
                                    "a1", "cmd", "command", None, True, 12, "test"
                                )
                                assert result["output"] == "result"

    @pytest.mark.asyncio
    async def test_with_cred_logs_audit(self):
        db = MagicMock()
        host = MagicMock()
        host.id = "h1"
        host.ip = "10.0.0.1"
        host.hostname = "srv"
        cred = {"id": "cr1", "username": "admin", "secret": "pass"}
        with patch("app.routers.c2._exec._mythic_execute", new_callable=AsyncMock,
                    return_value={"output": ""}):
            with patch("app.routers.c2._exec.new_id", return_value="ha1"):
                with patch("app.routers.c2._exec.ts_now", return_value="ts"):
                    with patch("app.core.secret_scrub.scrub_for_cred", side_effect=lambda x, y: x):
                        with patch("app.routers.c2._exec.bcast"):
                            with patch("app.routers.c2._exec.log_event"):
                                result, activity, rendered = await perform_c2_command(
                                    db, "p1", host, {"type": "mythic", "id": "c1"},
                                    "a1", "cmd", "command", cred, True, 12, "test",
                                    actor_username="user1"
                                )


class TestResolveC2Cred:
    @pytest.mark.asyncio
    async def test_no_credential_id(self):
        r = await resolve_c2_cred(MagicMock(), "p1", "", "rootnotes", {})
        assert r is None

    @pytest.mark.asyncio
    async def test_adaptix_c2_source(self):
        with patch("app.routers.c2._exec._adaptix_fetch_creds", new_callable=AsyncMock,
                    return_value=[{"c_creds_id": "c1", "id": "c1"}]):
            r = await resolve_c2_cred(MagicMock(), "p1", "c1", "c2", {"type": "adaptix", "id": "i1"})
            assert r is not None
            assert r["integration_id"] == "i1"

    @pytest.mark.asyncio
    async def test_rootnotes_cred(self):
        db = MagicMock()
        cred = MagicMock()
        cred.id = "cr1"
        cred.username = "admin"
        cred.secret = "enc:pass"
        cred.domain = "corp"
        cred.host = "10.0.0.1"
        cred.type = "plain"
        db.query.return_value.filter.return_value.first.return_value = cred
        with patch("app.routers.c2._exec.decrypt_str", return_value="pass"):
            r = await resolve_c2_cred(db, "p1", "cr1", "rootnotes", {"type": "sliver"})
            assert r["id"] == "cr1"

    @pytest.mark.asyncio
    async def test_rootnotes_not_found(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        r = await resolve_c2_cred(db, "p1", "cr1", "rootnotes", {"type": "sliver"})
        assert r is None
