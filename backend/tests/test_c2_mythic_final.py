import pytest
from unittest.mock import MagicMock

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

    def test_json_array_ip(self):
        assert _mythic_parse_ip({"ip": '["10.0.0.2"]'}) == "10.0.0.2"

    def test_json_array_first(self):
        assert _mythic_parse_ip({"ip": '["10.0.0.3", "10.0.0.4"]'}) == "10.0.0.3"

    def test_fallback_external(self):
        assert _mythic_parse_ip({"ip": "", "external_ip": "1.2.3.4"}) == "1.2.3.4"

    def test_empty(self):
        assert _mythic_parse_ip({}) == ""

    def test_invalid_json_array(self):
        assert _mythic_parse_ip({"ip": "[not-json]", "external_ip": "5.5.5.5"}) == "[not-json]"


class TestMythicCbNote:
    def test_full(self):
        cb = {"description": "test", "integrity_level": 3, "process_name": "cmd.exe", "pid": 42, "last_checkin": "2025-01-01"}
        note = _mythic_cb_note(cb)
        assert "test" in note
        assert "Integrity: 3" in note
        assert "cmd.exe" in note
        assert "42" in note

    def test_empty(self):
        assert _mythic_cb_note({}) == ""


class TestMythicCbToHost:
    def test_basic(self):
        cb = {"ip": "10.0.0.1", "host": "SRV1", "os": "Windows", "domain": "corp", "user": "admin", "architecture": "x64", "process_name": "implant", "pid": 42, "active": True, "agent_callback_id": "cb-1", "id": 1}
        result = _mythic_cb_to_host(cb)
        assert result["ip"] == "10.0.0.1"
        assert result["hostname"] == "SRV1"
        assert result["alive"] is True
        assert result["source"] == "mythic"

    def test_no_ip(self):
        cb = {"ip": "", "external_ip": ""}
        assert _mythic_cb_to_host(cb) is None

    def test_empty(self):
        assert _mythic_cb_to_host(None) is None
        assert _mythic_cb_to_host({}) is None

    def test_inactive(self):
        cb = {"ip": "10.0.0.1", "active": False}
        result = _mythic_cb_to_host(cb)
        assert result["beacon_id"] == ""


class TestMythicCredResult:
    def test_basic(self):
        c = {"account": "admin", "credential_text": "pass", "type": "plaintext", "realm": "corp"}
        result = _mythic_cred_result(c)
        assert result["username"] == "admin"
        assert result["type"] == "plain"

    def test_hash_type(self):
        c = {"account": "admin", "credential_text": "abc", "type": "ntlm_hash"}
        result = _mythic_cred_result(c)
        assert result["type"] == "hash"

    def test_kerberos_type(self):
        c = {"account": "svc", "credential_text": "tkt", "type": "kerberos_ticket"}
        result = _mythic_cred_result(c)
        assert result["type"] == "hash"

    def test_empty_account(self):
        assert _mythic_cred_result({"account": ""}) is None

    def test_empty_dict(self):
        assert _mythic_cred_result({}) is None

    def test_none(self):
        assert _mythic_cred_result(None) is None


class TestMythicResolveCallbackDbId:
    def test_numeric(self):
        assert _mythic_resolve_callback_db_id("42") == 42

    def test_non_numeric(self):
        assert _mythic_resolve_callback_db_id("abc") is None

    def test_none(self):
        assert _mythic_resolve_callback_db_id(None) is None


class TestBuildMythicTaskDict:
    def test_basic(self):
        t = {"id": 1, "display_id": 2, "command_name": "shell", "params": "whoami", "completed": True, "timestamp": "2025-01-01", "status": "completed", "responses": [], "operator": {"username": "admin"}}
        result = _build_mythic_task_dict(t)
        assert result["task_id"] == 1
        assert result["completed"] is True
        assert result["user"] == "admin"

    def test_with_stdout(self):
        t = {"id": 1, "display_id": 2, "command_name": "shell", "params": "", "completed": False, "timestamp": "", "status": "", "responses": [], "stdout": "output"}
        result = _build_mythic_task_dict(t)
        assert "output" in result["text"]
