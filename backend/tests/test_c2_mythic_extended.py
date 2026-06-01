"""Extended tests for app.routers.c2._mythic — helper functions."""
import pytest

from app.routers.c2._mythic import (
    _mythic_parse_ip,
    _mythic_cb_note,
    _mythic_cb_to_host,
    _mythic_cred_result,
    _mythic_resolve_callback_db_id,
    _build_mythic_task_dict,
)


class TestMythicParseIp:
    def test_plain_ip(self):
        assert _mythic_parse_ip({"ip": "10.0.0.1"}) == "10.0.0.1"

    def test_json_array(self):
        assert _mythic_parse_ip({"ip": '["10.0.0.2"]'}) == "10.0.0.2"

    def test_empty_ip_uses_external(self):
        assert _mythic_parse_ip({"ip": "", "external_ip": "1.2.3.4"}) == "1.2.3.4"

    def test_invalid_json_array(self):
        assert _mythic_parse_ip({"ip": "[invalid"}) == "[invalid"

    def test_empty_array(self):
        assert _mythic_parse_ip({"ip": "[]"}) == "[]"

    def test_both_empty(self):
        assert _mythic_parse_ip({}) == ""


class TestMythicCbNote:
    def test_full(self):
        note = _mythic_cb_note({
            "description": "desc",
            "integrity_level": 3,
            "process_name": "cmd.exe",
            "pid": 123,
            "last_checkin": "2025-01-01",
        })
        assert "desc" in note
        assert "Integrity: 3" in note
        assert "cmd.exe" in note

    def test_empty(self):
        assert _mythic_cb_note({}) == ""


class TestMythicCbToHost:
    def test_basic(self):
        result = _mythic_cb_to_host({
            "ip": "10.0.0.1",
            "host": "PC1",
            "os": "Windows",
            "domain": "dom",
            "user": "admin",
            "architecture": "x64",
            "process_name": "implant",
            "pid": 123,
            "active": True,
            "agent_callback_id": "cb-1",
            "id": "1",
        })
        assert result["ip"] == "10.0.0.1"
        assert result["alive"] is True
        assert result["beacon_id"] == "cb-1"
        assert result["source"] == "mythic"

    def test_dead_no_beacon(self):
        result = _mythic_cb_to_host({
            "ip": "10.0.0.1", "active": False, "agent_callback_id": "cb-1",
        })
        assert result["alive"] is False
        assert result["beacon_id"] == ""

    def test_no_ip_returns_none(self):
        result = _mythic_cb_to_host({"ip": ""})
        assert result is None

    def test_empty_cb_returns_none(self):
        assert _mythic_cb_to_host({}) is None
        assert _mythic_cb_to_host(None) is None


class TestMythicCredResult:
    def test_basic(self):
        result = _mythic_cred_result({
            "account": "admin",
            "credential_text": "pass",
            "type": "plaintext",
            "realm": "DOMAIN",
        })
        assert result["username"] == "admin"
        assert result["type"] == "plain"

    def test_hash_type(self):
        result = _mythic_cred_result({"account": "u", "type": "hash"})
        assert result["type"] == "hash"

    def test_kerberos_type(self):
        result = _mythic_cred_result({"account": "u", "type": "kerberos_ticket"})
        assert result["type"] == "hash"

    def test_empty_returns_none(self):
        assert _mythic_cred_result({}) is None
        assert _mythic_cred_result({"account": ""}) is None


class TestMythicResolveCallbackDbId:
    def test_valid_int(self):
        assert _mythic_resolve_callback_db_id("42") == 42

    def test_invalid(self):
        assert _mythic_resolve_callback_db_id("abc") is None

    def test_none(self):
        assert _mythic_resolve_callback_db_id(None) is None


class TestBuildMythicTaskDict:
    def test_basic(self):
        t = {
            "id": 1, "display_id": 10, "command_name": "shell",
            "params": "whoami", "status": "completed", "completed": True,
            "timestamp": "2025-01-01", "responses": [{"response_text": "admin"}],
            "stdout": "out", "operator": {"username": "op1"},
        }
        result = _build_mythic_task_dict(t)
        assert result["task_id"] == 1
        assert result["completed"] is True
        assert "admin" in result["text"]
        assert result["user"] == "op1"

    def test_no_responses(self):
        t = {"id": 2, "display_id": 20, "command_name": "shell",
             "params": "", "status": "", "completed": False, "timestamp": "",
             "responses": [], "operator": {}}
        result = _build_mythic_task_dict(t)
        assert result["text"] == ""
