"""Tests for C2 Mythic helper functions."""
import pytest

from app.routers.c2._mythic import (
    _mythic_parse_ip,
    _mythic_cb_note,
    _mythic_cb_to_host,
    _mythic_cred_result,
    _mythic_resolve_callback_db_id,
    _build_mythic_task_dict,
    _MYTHIC_CALLBACK_FIELDS,
    _MYTHIC_CRED_FIELDS,
)


class TestMythicParseIp:
    def test_plain_ip(self):
        assert _mythic_parse_ip({"ip": "10.0.0.1"}) == "10.0.0.1"

    def test_json_array_ip(self):
        cb = {"ip": '["10.0.0.1", "10.0.0.2"]'}
        assert _mythic_parse_ip(cb) == "10.0.0.1"

    def test_empty_ip_uses_external(self):
        assert _mythic_parse_ip({"ip": "", "external_ip": "1.2.3.4"}) == "1.2.3.4"

    def test_invalid_json_falls_back(self):
        cb = {"ip": "[not json]", "external_ip": "5.5.5.5"}
        assert _mythic_parse_ip(cb) == "[not json]"

    def test_empty_everything(self):
        assert _mythic_parse_ip({}) == ""

    def test_json_array_with_non_string(self):
        cb = {"ip": "[1]"}
        result = _mythic_parse_ip(cb)
        assert result == "1"

    def test_empty_json_array(self):
        cb = {"ip": "[]", "external_ip": "fallback"}
        assert _mythic_parse_ip(cb) == "[]"


class TestMythicCbNote:
    def test_full_note(self):
        cb = {
            "description": "Callback desc",
            "integrity_level": 3,
            "process_name": "cmd.exe",
            "pid": 1234,
            "last_checkin": "2025-01-01",
        }
        note = _mythic_cb_note(cb)
        assert "Callback desc" in note
        assert "Integrity: 3" in note
        assert "cmd.exe" in note
        assert "PID 1234" in note
        assert "Last check-in: 2025-01-01" in note

    def test_empty_note(self):
        assert _mythic_cb_note({}) == ""

    def test_description_only(self):
        assert _mythic_cb_note({"description": "hello"}) == "hello"

    def test_zero_integrity_included(self):
        assert "Integrity: 0" in _mythic_cb_note({"integrity_level": 0})

    def test_none_integrity_not_included(self):
        note = _mythic_cb_note({"integrity_level": None})
        assert "Integrity" not in note


class TestMythicCbToHost:
    def test_basic_conversion(self):
        cb = {
            "ip": "10.0.0.1",
            "host": "PC1",
            "os": "Windows",
            "domain": "corp",
            "user": "admin",
            "architecture": "x64",
            "process_name": "explorer",
            "pid": 42,
            "active": True,
            "agent_callback_id": "abc123",
            "id": "cb1",
        }
        result = _mythic_cb_to_host(cb)
        assert result["ip"] == "10.0.0.1"
        assert result["hostname"] == "PC1"
        assert result["os"] == "Windows"
        assert result["username"] == "admin"
        assert result["alive"] is True
        assert result["beacon_id"] == "abc123"
        assert result["source"] == "mythic"

    def test_empty_cb_returns_none(self):
        assert _mythic_cb_to_host(None) is None
        assert _mythic_cb_to_host({}) is None

    def test_no_ip_returns_none(self):
        assert _mythic_cb_to_host({"ip": ""}) is None

    def test_inactive_sets_empty_beacon_id(self):
        cb = {"ip": "10.0.0.1", "active": False, "agent_callback_id": "abc"}
        result = _mythic_cb_to_host(cb)
        assert result["beacon_id"] == ""

    def test_defaults_active_true(self):
        cb = {"ip": "10.0.0.1"}
        result = _mythic_cb_to_host(cb)
        assert result["alive"] is True

    def test_id_fallback_for_beacon(self):
        cb = {"ip": "10.0.0.1", "active": True, "id": "cb42"}
        result = _mythic_cb_to_host(cb)
        assert result["beacon_id"] == "cb42"


class TestMythicCredResult:
    def test_basic_cred(self):
        c = {"account": "admin", "credential_text": "pass", "type": "plaintext", "realm": "CORP"}
        result = _mythic_cred_result(c)
        assert result["username"] == "admin"
        assert result["secret"] == "pass"
        assert result["type"] == "plain"
        assert result["realm"] == "CORP"
        assert result["source"] == "mythic"

    def test_empty_returns_none(self):
        assert _mythic_cred_result(None) is None
        assert _mythic_cred_result({}) is None

    def test_no_account_returns_none(self):
        assert _mythic_cred_result({"credential_text": "x"}) is None

    def test_hash_type(self):
        c = {"account": "u", "type": "hash"}
        assert _mythic_cred_result(c)["type"] == "hash"

    def test_ntlm_type(self):
        c = {"account": "u", "type": "ntlm"}
        assert _mythic_cred_result(c)["type"] == "hash"

    def test_kerberos_type(self):
        c = {"account": "u", "type": "kerberos_ticket"}
        assert _mythic_cred_result(c)["type"] == "hash"

    def test_default_type(self):
        c = {"account": "u", "type": "plaintext"}
        assert _mythic_cred_result(c)["type"] == "plain"


class TestMythicResolveCallbackDbId:
    def test_numeric_string(self):
        assert _mythic_resolve_callback_db_id("42") == 42

    def test_uuid_returns_none(self):
        assert _mythic_resolve_callback_db_id("abc-def-ghi") is None

    def test_none_returns_none(self):
        assert _mythic_resolve_callback_db_id(None) is None

    def test_empty_returns_none(self):
        assert _mythic_resolve_callback_db_id("") is None


class TestBuildMythicTaskDict:
    def test_basic_task(self):
        t = {
            "id": 1,
            "display_id": 100,
            "command_name": "shell",
            "params": "whoami",
            "completed": True,
            "responses": [{"response_text": "admin"}],
            "status": "completed",
            "timestamp": "2025-01-01",
            "operator": {"username": "op1"},
        }
        result = _build_mythic_task_dict(t)
        assert result["task_id"] == 1
        assert result["cmdline"] == "shell whoami"
        assert result["completed"] is True
        assert result["text"] == "admin"
        assert result["user"] == "op1"

    def test_with_stdout(self):
        t = {"id": 2, "stdout": "output text", "responses": [], "command_name": "ls", "params": ""}
        result = _build_mythic_task_dict(t)
        assert "output text" in result["text"]

    def test_no_responses(self):
        t = {"id": 3, "responses": None, "command_name": "x", "params": ""}
        result = _build_mythic_task_dict(t)
        assert result["text"] == ""

    def test_empty_operator(self):
        t = {"id": 4, "operator": None, "command_name": "", "params": ""}
        result = _build_mythic_task_dict(t)
        assert result["user"] == ""


class TestMythicConstants:
    def test_callback_fields_not_empty(self):
        assert "id" in _MYTHIC_CALLBACK_FIELDS
        assert "host" in _MYTHIC_CALLBACK_FIELDS

    def test_cred_fields_not_empty(self):
        assert "account" in _MYTHIC_CRED_FIELDS
        assert "credential_text" in _MYTHIC_CRED_FIELDS
