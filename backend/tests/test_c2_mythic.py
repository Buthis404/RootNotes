"""Consolidated tests for test_c2_mythic (merged variant files)."""

# ════════ from test_c2_mythic_api.py ════════
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


class TestMythicParseIp_api:
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


class TestMythicCbNote_api:
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


class TestMythicCbToHost_api:
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


class TestMythicCredResult_api:
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


class TestMythicResolveCallbackDbId_api:
    def test_numeric_string(self):
        assert _mythic_resolve_callback_db_id("42") == 42

    def test_uuid_returns_none(self):
        assert _mythic_resolve_callback_db_id("abc-def-ghi") is None

    def test_none_returns_none(self):
        assert _mythic_resolve_callback_db_id(None) is None

    def test_empty_returns_none(self):
        assert _mythic_resolve_callback_db_id("") is None


class TestBuildMythicTaskDict_api:
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


# ════════ from test_c2_mythic_extended.py ════════
import pytest

from app.routers.c2._mythic import (
    _mythic_parse_ip,
    _mythic_cb_note,
    _mythic_cb_to_host,
    _mythic_cred_result,
    _mythic_resolve_callback_db_id,
    _build_mythic_task_dict,
)


class TestMythicParseIp_extended:
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


class TestMythicCbNote_extended:
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


class TestMythicCbToHost_extended:
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


class TestMythicCredResult_extended:
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


class TestMythicResolveCallbackDbId_extended:
    def test_valid_int(self):
        assert _mythic_resolve_callback_db_id("42") == 42

    def test_invalid(self):
        assert _mythic_resolve_callback_db_id("abc") is None

    def test_none(self):
        assert _mythic_resolve_callback_db_id(None) is None


class TestBuildMythicTaskDict_extended:
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


# ════════ from test_c2_mythic_final.py ════════
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


class TestMythicParseIp_final:
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


class TestMythicCbNote_final:
    def test_full(self):
        cb = {"description": "test", "integrity_level": 3, "process_name": "cmd.exe", "pid": 42, "last_checkin": "2025-01-01"}
        note = _mythic_cb_note(cb)
        assert "test" in note
        assert "Integrity: 3" in note
        assert "cmd.exe" in note
        assert "42" in note

    def test_empty(self):
        assert _mythic_cb_note({}) == ""


class TestMythicCbToHost_final:
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


class TestMythicCredResult_final:
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


class TestMythicResolveCallbackDbId_final:
    def test_numeric(self):
        assert _mythic_resolve_callback_db_id("42") == 42

    def test_non_numeric(self):
        assert _mythic_resolve_callback_db_id("abc") is None

    def test_none(self):
        assert _mythic_resolve_callback_db_id(None) is None


class TestBuildMythicTaskDict_final:
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


# ════════ from test_c2_mythic_final2.py ════════
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


class TestMythicParseIp_final2:
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


class TestMythicCbNote_final2:
    def test_full(self):
        cb = {"description": "desc", "integrity_level": 3, "process_name": "proc", "pid": 42, "last_checkin": "now"}
        r = _mythic_cb_note(cb)
        assert "desc" in r
        assert "3" in r
        assert "proc" in r
        assert "now" in r

    def test_empty(self):
        assert _mythic_cb_note({}) == ""


class TestMythicCbToHost_final2:
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


class TestMythicCredResult_final2:
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


class TestMythicResolveCallbackDbId_final2:
    def test_int(self):
        assert _mythic_resolve_callback_db_id("42") == 42

    def test_non_int(self):
        assert _mythic_resolve_callback_db_id("abc") is None

    def test_none(self):
        assert _mythic_resolve_callback_db_id(None) is None


class TestBuildMythicTaskDict_final2:
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


# ════════ from test_c2_mythic_v3.py ════════
import pytest
import json
from unittest.mock import MagicMock, patch, AsyncMock
from fastapi import HTTPException
import httpx

from app.routers.c2._mythic import (
    _mythic_auth_headers,
    _mythic_graphql,
    _mythic_parse_ip,
    _mythic_cb_to_host,
    _mythic_cred_result,
    _mythic_resolve_callback_db_id,
    _build_mythic_task_dict,
    _mythic_cb_note,
    _mythic_sync,
    _mythic_ensure_cb_id,
    _mythic_poll_task,
    _mythic_execute,
    _mythic_live_agents,
    _mythic_fetch_agent_tasks,
)


class TestMythicAuthHeaders:
    @pytest.mark.asyncio
    async def test_token(self):
        client = MagicMock()
        r = await _mythic_auth_headers({"token": "mytoken"}, client)
        assert r == {"apitoken": "mytoken"}

    @pytest.mark.asyncio
    async def test_password_login(self):
        client = MagicMock()
        resp = MagicMock()
        resp.json.return_value = {"access_token": "jwt123"}
        resp.raise_for_status = MagicMock()
        client.post = AsyncMock(return_value=resp)
        r = await _mythic_auth_headers({"url": "http://mythic", "username": "u", "password": "p"}, client)
        assert r == {"Authorization": "Bearer jwt123"}

    @pytest.mark.asyncio
    async def test_password_login_token_key(self):
        client = MagicMock()
        resp = MagicMock()
        resp.json.return_value = {"token": "jwt456"}
        resp.raise_for_status = MagicMock()
        client.post = AsyncMock(return_value=resp)
        r = await _mythic_auth_headers({"url": "http://mythic"}, client)
        assert r == {"Authorization": "Bearer jwt456"}

    @pytest.mark.asyncio
    async def test_password_login_no_token(self):
        client = MagicMock()
        resp = MagicMock()
        resp.json.return_value = {}
        resp.raise_for_status = MagicMock()
        client.post = AsyncMock(return_value=resp)
        with pytest.raises(HTTPException) as exc_info:
            await _mythic_auth_headers({"url": "http://mythic"}, client)
        assert exc_info.value.status_code == 400


class TestMythicGraphql:
    @pytest.mark.asyncio
    async def test_success(self):
        client = MagicMock()
        resp = MagicMock()
        resp.json.return_value = {"data": {"callback": []}}
        resp.raise_for_status = MagicMock()
        client.post = AsyncMock(return_value=resp)
        r = await _mythic_graphql({"url": "http://m"}, client, "query {}", {})
        assert r == {"callback": []}

    @pytest.mark.asyncio
    async def test_graphql_error(self):
        client = MagicMock()
        resp = MagicMock()
        resp.json.return_value = {"errors": ["bad"]}
        resp.raise_for_status = MagicMock()
        client.post = AsyncMock(return_value=resp)
        with pytest.raises(HTTPException) as exc_info:
            await _mythic_graphql({"url": "http://m"}, client, "query {}", {})
        assert exc_info.value.status_code == 400


class TestMythicSync:
    @pytest.mark.asyncio
    async def test_basic(self):
        mock_auth = AsyncMock(return_value={"apitoken": "t"})
        mock_gql = AsyncMock(return_value={
            "callback": [{"ip": "10.0.0.1", "host": "srv", "active": True}],
            "credential": [{"account": "admin", "credential_text": "x"}],
        })
        with patch("app.routers.c2._mythic._mythic_auth_headers", mock_auth):
            with patch("app.routers.c2._mythic._mythic_graphql", mock_gql):
                r = await _mythic_sync({"url": "http://m", "verify_ssl": False})
                assert len(r["hosts"]) == 1
                assert len(r["creds"]) == 1


class TestMythicEnsureCbId:
    @pytest.mark.asyncio
    async def test_already_set(self):
        r = await _mythic_ensure_cb_id({}, MagicMock(), {}, 42, "abc")
        assert r == 42

    @pytest.mark.asyncio
    async def test_lookup(self):
        mock_gql = AsyncMock(return_value={"callback": [{"id": 99}]})
        with patch("app.routers.c2._mythic._mythic_graphql", mock_gql):
            r = await _mythic_ensure_cb_id({}, MagicMock(), {}, None, "abc")
            assert r == 99

    @pytest.mark.asyncio
    async def test_lookup_empty(self):
        mock_gql = AsyncMock(return_value={"callback": []})
        with patch("app.routers.c2._mythic._mythic_graphql", mock_gql):
            with pytest.raises(HTTPException) as exc_info:
                await _mythic_ensure_cb_id({}, MagicMock(), {}, None, "abc")
            assert exc_info.value.status_code == 404


class TestMythicPollTask:
    @pytest.mark.asyncio
    async def test_completed_immediately(self):
        mock_gql = AsyncMock(return_value={
            "task": [{"id": 1, "completed": True, "status": "completed", "stdout": "out",
                      "responses": []}]
        })
        with patch("app.routers.c2._mythic._mythic_graphql", mock_gql):
            with patch("app.routers.c2._mythic.utcnow") as mock_now:
                from datetime import datetime, timezone
                t0 = datetime(2024, 1, 1, tzinfo=timezone.utc)
                mock_now.side_effect = [t0, t0]
                r = await _mythic_poll_task({}, MagicMock(), {}, 1, 10)
                assert r["completed"] is True


class TestMythicExecute:
    @pytest.mark.asyncio
    async def test_basic_no_wait(self):
        mock_auth = AsyncMock(return_value={"apitoken": "t"})
        mock_gql = AsyncMock(return_value={
            "createTask": {"id": 10, "display_id": 1, "status": "submitted", "error": None}
        })
        with patch("app.routers.c2._mythic._mythic_auth_headers", mock_auth):
            with patch("app.routers.c2._mythic._mythic_graphql", mock_gql):
                with patch("app.routers.c2._mythic._mythic_resolve_callback_db_id", return_value=5):
                    r = await _mythic_execute({"url": "http://m", "verify_ssl": False},
                                              "5", "whoami", wait_for_output=False)
                    assert r["accepted"] is True
                    assert r["task_id"] == 10

    @pytest.mark.asyncio
    async def test_with_bang_command(self):
        mock_auth = AsyncMock(return_value={"apitoken": "t"})
        mock_gql = AsyncMock(return_value={
            "createTask": {"id": 11, "display_id": 2, "status": "submitted", "error": None}
        })
        with patch("app.routers.c2._mythic._mythic_auth_headers", mock_auth):
            with patch("app.routers.c2._mythic._mythic_graphql", mock_gql):
                with patch("app.routers.c2._mythic._mythic_resolve_callback_db_id", return_value=5):
                    r = await _mythic_execute({"url": "http://m", "verify_ssl": False},
                                              "5", "!shell whoami", wait_for_output=False)
                    assert r["command"] == "shell"

    @pytest.mark.asyncio
    async def test_create_task_error(self):
        mock_auth = AsyncMock(return_value={"apitoken": "t"})
        mock_gql = AsyncMock(return_value={
            "createTask": {"id": 12, "error": "bad command"}
        })
        with patch("app.routers.c2._mythic._mythic_auth_headers", mock_auth):
            with patch("app.routers.c2._mythic._mythic_graphql", mock_gql):
                with patch("app.routers.c2._mythic._mythic_resolve_callback_db_id", return_value=5):
                    with pytest.raises(HTTPException) as exc_info:
                        await _mythic_execute({"url": "http://m", "verify_ssl": False},
                                              "5", "cmd", wait_for_output=False)
                    assert exc_info.value.status_code == 400


class TestMythicLiveAgents:
    @pytest.mark.asyncio
    async def test_basic(self):
        mock_auth = AsyncMock(return_value={"apitoken": "t"})
        mock_gql = AsyncMock(return_value={
            "callback": [
                {"ip": "10.0.0.1", "host": "srv", "active": True, "user": "admin",
                 "domain": "corp", "os": "Win", "architecture": "x64",
                 "process_name": "p", "agent_callback_id": "cb1", "last_checkin": "now"},
            ]
        })
        with patch("app.routers.c2._mythic._mythic_auth_headers", mock_auth):
            with patch("app.routers.c2._mythic._mythic_graphql", mock_gql):
                r = await _mythic_live_agents({"url": "http://m", "verify_ssl": False})
                assert len(r) == 1
                assert r[0]["ip"] == "10.0.0.1"


class TestMythicFetchAgentTasks:
    @pytest.mark.asyncio
    async def test_basic(self):
        mock_auth = AsyncMock(return_value={"apitoken": "t"})
        mock_gql = AsyncMock(return_value={
            "task": [
                {"id": 1, "display_id": 1, "command_name": "shell", "params": "whoami",
                 "status": "completed", "completed": True, "timestamp": "now",
                 "stdout": "root", "responses": [],
                 "operator": {"username": "admin"}},
            ]
        })
        with patch("app.routers.c2._mythic._mythic_auth_headers", mock_auth):
            with patch("app.routers.c2._mythic._mythic_graphql", mock_gql):
                r = await _mythic_fetch_agent_tasks(
                    {"url": "http://m", "verify_ssl": False}, "1", limit=10
                )
                assert len(r) == 1
                assert r[0]["completed"] is True

    @pytest.mark.asyncio
    async def test_string_callback_id_lookup(self):
        mock_auth = AsyncMock(return_value={"apitoken": "t"})
        gql_responses = [
            {"callback": [{"id": 42}]},
            {"task": []},
        ]
        mock_gql = AsyncMock(side_effect=gql_responses)
        with patch("app.routers.c2._mythic._mythic_auth_headers", mock_auth):
            with patch("app.routers.c2._mythic._mythic_graphql", mock_gql):
                r = await _mythic_fetch_agent_tasks(
                    {"url": "http://m", "verify_ssl": False}, "abc123", limit=10
                )
                assert r == []
