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
    def test_simple(self):
        assert _mythic_parse_ip({"ip": "10.0.0.1"}) == "10.0.0.1"

    def test_json_array(self):
        assert _mythic_parse_ip({"ip": '["10.0.0.1", "10.0.0.2"]'}) == "10.0.0.1"

    def test_invalid_json_array(self):
        result = _mythic_parse_ip({"ip": "[invalid"})
        assert result == "[invalid" or result == ""

    def test_empty_fallback_external(self):
        assert _mythic_parse_ip({"ip": "", "external_ip": "1.1.1.1"}) == "1.1.1.1"

    def test_empty_all(self):
        assert _mythic_parse_ip({}) == ""


class TestMythicCbNote:
    def test_full(self):
        cb = {"description": "desc", "integrity_level": 3, "process_name": "proc", "pid": 42, "last_checkin": "now"}
        r = _mythic_cb_note(cb)
        assert "desc" in r
        assert "3" in r
        assert "proc" in r
        assert "now" in r

    def test_empty(self):
        assert _mythic_cb_note({}) == ""


class TestMythicCbToHost:
    def test_basic(self):
        cb = {"ip": "10.0.0.1", "host": "SRV", "os": "Win", "domain": "corp",
              "user": "admin", "architecture": "x64", "process_name": "p",
              "active": True, "agent_callback_id": "cb1"}
        r = _mythic_cb_to_host(cb)
        assert r["ip"] == "10.0.0.1"
        assert r["hostname"] == "SRV"
        assert r["source"] == "mythic"
        assert r["alive"] is True

    def test_empty(self):
        assert _mythic_cb_to_host({}) is None

    def test_no_ip(self):
        assert _mythic_cb_to_host({"ip": ""}) is None

    def test_dead_no_beacon(self):
        cb = {"ip": "10.0.0.1", "active": False, "agent_callback_id": "cb1", "id": "1"}
        r = _mythic_cb_to_host(cb)
        assert r["alive"] is False
        assert r["beacon_id"] == ""


class TestMythicCredResult:
    def test_empty(self):
        assert _mythic_cred_result({}) is None
        assert _mythic_cred_result(None) is None

    def test_no_account(self):
        assert _mythic_cred_result({"account": ""}) is None

    def test_hash_type(self):
        r = _mythic_cred_result({"account": "u", "credential_text": "x", "type": "ntlm"})
        assert r["type"] == "hash"

    def test_kerberos_type(self):
        r = _mythic_cred_result({"account": "u", "type": "kerberos_ticket"})
        assert r["type"] == "hash"

    def test_plain_type(self):
        r = _mythic_cred_result({"account": "u", "type": "plaintext"})
        assert r["type"] == "plain"


class TestMythicResolveCallbackDbId:
    def test_int(self):
        assert _mythic_resolve_callback_db_id("42") == 42

    def test_non_int(self):
        assert _mythic_resolve_callback_db_id("abc") is None

    def test_none(self):
        assert _mythic_resolve_callback_db_id(None) is None


class TestBuildMythicTaskDict:
    def test_full(self):
        t = {"id": 1, "display_id": 2, "command_name": "shell", "params": "whoami",
             "completed": True, "status": "completed", "timestamp": "now",
             "stdout": "root", "responses": [{"response_text": "line1"}],
             "operator": {"username": "admin"}}
        r = _build_mythic_task_dict(t)
        assert r["task_id"] == 1
        assert "root" in r["text"]
        assert r["completed"] is True
        assert r["user"] == "admin"

    def test_empty_responses(self):
        t = {"id": 1, "display_id": 2, "command_name": "shell", "params": "",
             "completed": False, "status": "", "timestamp": "", "responses": []}
        r = _build_mythic_task_dict(t)
        assert r["text"] == ""
