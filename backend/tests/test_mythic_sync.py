"""
Tests for the Mythic C2 connector (read-only P1 — sync + live_agents).

Mocks httpx so we exercise the parsing/normalization code without
needing a real Mythic teamserver.
"""
import json
from unittest.mock import AsyncMock, patch, MagicMock

import httpx
import pytest

from app.routers.c2 import (
    _mythic_sync,
    _mythic_live_agents,
    _mythic_auth_headers,
    _mythic_execute,
    _mythic_fetch_agent_tasks,
    _mythic_resolve_callback_db_id,
    _CONNECTORS,
    _LIVE_CONNECTORS,
    SUPPORTED_EXEC_C2_TYPES,
)


# ── Registration ───────────────────────────────────────────────────────

def test_mythic_registered_in_connectors():
    assert "mythic" in _CONNECTORS
    assert "mythic" in _LIVE_CONNECTORS


# ── Auth flow ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_auth_with_apitoken_skips_login():
    cfg = {"url": "https://mythic:7443", "token": "abc123"}
    client = AsyncMock()
    headers = await _mythic_auth_headers(cfg, client)
    assert headers == {"apitoken": "abc123"}
    client.post.assert_not_called()


@pytest.mark.asyncio
async def test_auth_with_username_password_logs_in():
    cfg = {"url": "https://mythic:7443", "username": "op", "password": "pw"}
    client = AsyncMock()
    response = MagicMock()
    response.json.return_value = {"access_token": "jwt-token", "user_id": 1}
    response.raise_for_status = MagicMock()
    client.post.return_value = response

    headers = await _mythic_auth_headers(cfg, client)

    assert headers == {"Authorization": "Bearer jwt-token"}
    client.post.assert_awaited_once()
    call_kwargs = client.post.await_args
    assert "/auth" in call_kwargs[0][0]
    assert call_kwargs[1]["json"]["username"] == "op"


@pytest.mark.asyncio
async def test_auth_login_without_token_raises():
    cfg = {"url": "https://mythic:7443", "username": "op", "password": "pw"}
    client = AsyncMock()
    response = MagicMock()
    response.json.return_value = {"error": "bad creds"}
    response.raise_for_status = MagicMock()
    client.post.return_value = response

    with pytest.raises(Exception):
        await _mythic_auth_headers(cfg, client)


# ── Sync: hosts/callbacks parsing ─────────────────────────────────────

def _make_async_client_mock(graphql_payload: dict):
    """Build an AsyncMock that emulates AsyncClient context manager and
    returns the given GraphQL payload on POST."""
    response = MagicMock()
    response.json.return_value = {"data": graphql_payload}
    response.raise_for_status = MagicMock()

    client = AsyncMock()
    client.post.return_value = response
    client.__aenter__.return_value = client
    client.__aexit__.return_value = None
    return client


@pytest.mark.asyncio
async def test_sync_parses_callbacks_to_hosts():
    callbacks = [
        {
            "id": 1,
            "agent_callback_id": "cb-uuid-1",
            "host": "DC01",
            "user": "Administrator",
            "domain": "CORP",
            "ip": "10.0.0.5",
            "external_ip": "1.2.3.4",
            "os": "Windows Server 2019",
            "architecture": "x64",
            "pid": 4242,
            "process_name": "explorer.exe",
            "active": True,
            "integrity_level": 3,
            "description": "DC compromise",
            "last_checkin": "2026-05-16T10:00:00Z",
        },
    ]
    client = _make_async_client_mock({"callback": callbacks, "credential": []})
    cfg = {"url": "https://mythic:7443", "token": "tok"}

    with patch.object(httpx, "AsyncClient", return_value=client):
        out = await _mythic_sync(cfg)

    assert len(out["hosts"]) == 1
    h = out["hosts"][0]
    assert h["ip"] == "10.0.0.5"
    assert h["hostname"] == "DC01"
    assert h["username"] == "Administrator"
    assert h["domain"] == "CORP"
    assert h["pid"] == 4242
    assert h["alive"] is True
    assert h["beacon_id"] == "cb-uuid-1"
    assert h["source"] == "mythic"
    assert "Integrity: 3" in h["note"]


@pytest.mark.asyncio
async def test_sync_handles_ip_as_json_array_string():
    """Mythic sometimes serializes callback.ip as a JSON list string."""
    callbacks = [
        {"id": 2, "agent_callback_id": "cb-2", "host": "WS01",
         "ip": '["10.0.0.7","fe80::1"]', "active": True},
    ]
    client = _make_async_client_mock({"callback": callbacks, "credential": []})
    cfg = {"url": "https://mythic:7443", "token": "tok"}

    with patch.object(httpx, "AsyncClient", return_value=client):
        out = await _mythic_sync(cfg)

    assert out["hosts"][0]["ip"] == "10.0.0.7"


@pytest.mark.asyncio
async def test_sync_falls_back_to_external_ip():
    callbacks = [
        {"id": 3, "agent_callback_id": "cb-3", "host": "WS02",
         "ip": "", "external_ip": "203.0.113.5", "active": True},
    ]
    client = _make_async_client_mock({"callback": callbacks, "credential": []})
    cfg = {"url": "https://mythic:7443", "token": "tok"}

    with patch.object(httpx, "AsyncClient", return_value=client):
        out = await _mythic_sync(cfg)

    assert out["hosts"][0]["ip"] == "203.0.113.5"


@pytest.mark.asyncio
async def test_sync_dead_callback_omits_beacon_id():
    callbacks = [
        {"id": 4, "agent_callback_id": "cb-4", "host": "WS03",
         "ip": "10.0.0.9", "active": False},
    ]
    client = _make_async_client_mock({"callback": callbacks, "credential": []})
    cfg = {"url": "https://mythic:7443", "token": "tok"}

    with patch.object(httpx, "AsyncClient", return_value=client):
        out = await _mythic_sync(cfg)

    h = out["hosts"][0]
    assert h["alive"] is False
    assert h["beacon_id"] == ""


# ── Sync: credentials parsing ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_sync_parses_plaintext_credential():
    creds = [
        {"id": 1, "account": "svc_sql", "realm": "CORP",
         "credential_text": "P@ssw0rd!", "type": "plaintext", "comment": ""},
    ]
    client = _make_async_client_mock({"callback": [], "credential": creds})
    cfg = {"url": "https://mythic:7443", "token": "tok"}

    with patch.object(httpx, "AsyncClient", return_value=client):
        out = await _mythic_sync(cfg)

    assert len(out["creds"]) == 1
    c = out["creds"][0]
    assert c["username"] == "svc_sql"
    assert c["secret"] == "P@ssw0rd!"
    assert c["type"] == "plain"
    assert c["realm"] == "CORP"
    assert c["source"] == "mythic"


@pytest.mark.asyncio
async def test_sync_classifies_hash_credential():
    creds = [
        {"id": 1, "account": "admin", "realm": "CORP",
         "credential_text": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
         "type": "ntlm_hash"},
        {"id": 2, "account": "krbtgt", "realm": "CORP",
         "credential_text": "deadbeef", "type": "kerberos_ticket"},
    ]
    client = _make_async_client_mock({"callback": [], "credential": creds})
    cfg = {"url": "https://mythic:7443", "token": "tok"}

    with patch.object(httpx, "AsyncClient", return_value=client):
        out = await _mythic_sync(cfg)

    assert all(c["type"] == "hash" for c in out["creds"])


@pytest.mark.asyncio
async def test_sync_skips_credential_without_account():
    creds = [
        {"id": 1, "account": "", "realm": "CORP", "credential": "xxx"},
        {"id": 2, "account": "valid", "realm": "CORP", "credential": "yyy"},
    ]
    client = _make_async_client_mock({"callback": [], "credential": creds})
    cfg = {"url": "https://mythic:7443", "token": "tok"}

    with patch.object(httpx, "AsyncClient", return_value=client):
        out = await _mythic_sync(cfg)

    assert len(out["creds"]) == 1
    assert out["creds"][0]["username"] == "valid"


# ── Live agents ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_live_agents_returns_callback_summary():
    callbacks = [
        {"id": 1, "agent_callback_id": "cb-1", "host": "DC01",
         "user": "admin", "domain": "CORP", "ip": "10.0.0.5",
         "os": "Windows", "architecture": "x64", "process_name": "lsass.exe",
         "active": True, "last_checkin": "2026-05-16T10:00:00Z"},
        {"id": 2, "agent_callback_id": "cb-2", "host": "WS01",
         "ip": "10.0.0.6", "active": False},
    ]
    client = _make_async_client_mock({"callback": callbacks})
    cfg = {"url": "https://mythic:7443", "token": "tok"}

    with patch.object(httpx, "AsyncClient", return_value=client):
        out = await _mythic_live_agents(cfg)

    assert len(out) == 2
    assert out[0]["mark"] == "alive"
    assert out[0]["beacon_id"] == "cb-1"
    assert out[1]["mark"] == "dead"


# ── GraphQL error surfacing ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_sync_surfaces_graphql_errors():
    response = MagicMock()
    response.json.return_value = {"errors": [{"message": "permission denied"}]}
    response.raise_for_status = MagicMock()

    client = AsyncMock()
    client.post.return_value = response
    client.__aenter__.return_value = client
    client.__aexit__.return_value = None

    cfg = {"url": "https://mythic:7443", "token": "tok"}
    with patch.object(httpx, "AsyncClient", return_value=client):
        with pytest.raises(Exception) as excinfo:
            await _mythic_sync(cfg)
    assert "permission denied" in str(excinfo.value)


# ── Execute & tasks (P2) ──────────────────────────────────────────────

def test_mythic_in_supported_exec_types():
    assert "mythic" in SUPPORTED_EXEC_C2_TYPES


def test_resolve_callback_db_id_numeric():
    assert _mythic_resolve_callback_db_id("42") == 42
    assert _mythic_resolve_callback_db_id("not-a-number") is None
    assert _mythic_resolve_callback_db_id("") is None


def _multi_response_mock(payloads):
    """AsyncMock that returns successive GraphQL payloads (dicts) for
    consecutive POSTs."""
    responses = []
    for payload in payloads:
        r = MagicMock()
        r.json.return_value = {"data": payload}
        r.raise_for_status = MagicMock()
        responses.append(r)
    client = AsyncMock()
    client.post.side_effect = responses
    client.__aenter__.return_value = client
    client.__aexit__.return_value = None
    return client


@pytest.mark.asyncio
async def test_execute_creates_task_and_returns_immediately_when_no_wait():
    client = _multi_response_mock([
        {"createTask": {"id": 7, "display_id": 1, "status": "submitted", "error": None}},
    ])
    cfg = {"url": "https://mythic:7443", "token": "tok"}

    with patch.object(httpx, "AsyncClient", return_value=client):
        out = await _mythic_execute(cfg, "42", "whoami", wait_for_output=False)

    assert out["accepted"] is True
    assert out["task_id"] == 7
    assert out["display_id"] == 1
    assert out["command"] == "shell"
    # No poll calls
    assert client.post.await_count == 1


@pytest.mark.asyncio
async def test_execute_polls_until_completed():
    client = _multi_response_mock([
        {"createTask": {"id": 9, "display_id": 2, "status": "submitted", "error": None}},
        {"task": [{"id": 9, "status": "processing", "completed": False, "stdout": "", "stderr": "", "responses": []}]},
        {"task": [{"id": 9, "status": "completed", "completed": True, "stdout": "", "stderr": "",
                   "responses": [{"response_text": "nt authority\\system", "is_error": False}]}]},
    ])
    cfg = {"url": "https://mythic:7443", "token": "tok"}

    with patch.object(httpx, "AsyncClient", return_value=client):
        out = await _mythic_execute(cfg, "42", "whoami", wait_for_output=True, timeout_seconds=3)

    assert out["output"] == "nt authority\\system"
    assert client.post.await_count == 3


@pytest.mark.asyncio
async def test_execute_supports_command_prefix_override():
    """A `!cmd args` prefix routes to a non-default Mythic command."""
    client = _multi_response_mock([
        {"createTask": {"id": 11, "display_id": 3, "status": "submitted", "error": None}},
    ])
    cfg = {"url": "https://mythic:7443", "token": "tok"}

    with patch.object(httpx, "AsyncClient", return_value=client):
        out = await _mythic_execute(cfg, "42", "!run beacon.exe", wait_for_output=False)

    assert out["command"] == "run"
    # Verify the mutation body contains the right command + params
    call_args = client.post.await_args
    body = call_args[1]["json"]["query"]
    assert 'command: "run"' in body
    assert '"beacon.exe"' in body


@pytest.mark.asyncio
async def test_execute_resolves_uuid_callback_id_via_lookup():
    client = _multi_response_mock([
        {"callback": [{"id": 99}]},
        {"createTask": {"id": 13, "display_id": 4, "status": "submitted", "error": None}},
    ])
    cfg = {"url": "https://mythic:7443", "token": "tok"}

    with patch.object(httpx, "AsyncClient", return_value=client):
        out = await _mythic_execute(cfg, "cb-uuid-abc", "ls", wait_for_output=False)

    assert out["task_id"] == 13
    # First call should be the UUID lookup, second the createTask
    assert client.post.await_count == 2
    first_body = client.post.await_args_list[0][1]["json"]["query"]
    assert "cb-uuid-abc" in first_body
    assert "agent_callback_id" in first_body


@pytest.mark.asyncio
async def test_execute_uuid_not_found_raises_404():
    client = _multi_response_mock([
        {"callback": []},
    ])
    cfg = {"url": "https://mythic:7443", "token": "tok"}

    with patch.object(httpx, "AsyncClient", return_value=client):
        with pytest.raises(Exception) as excinfo:
            await _mythic_execute(cfg, "nonexistent-uuid", "ls", wait_for_output=False)
    assert "not found" in str(excinfo.value).lower()


@pytest.mark.asyncio
async def test_execute_createTask_error_raises():
    client = _multi_response_mock([
        {"createTask": {"id": None, "status": "error", "error": "OPSEC violation"}},
    ])
    cfg = {"url": "https://mythic:7443", "token": "tok"}

    with patch.object(httpx, "AsyncClient", return_value=client):
        with pytest.raises(Exception) as excinfo:
            await _mythic_execute(cfg, "42", "rm -rf /", wait_for_output=False)
    assert "OPSEC" in str(excinfo.value)


@pytest.mark.asyncio
async def test_fetch_agent_tasks_returns_normalized_rows():
    client = _multi_response_mock([
        {"task": [
            {"id": 1, "display_id": 10, "command_name": "shell", "params": "whoami",
             "status": "completed", "completed": True, "timestamp": "2026-05-16T10:00:00Z",
             "stdout": "", "stderr": "",
             "responses": [{"response_text": "user1", "is_error": False}],
             "operator": {"username": "op1"}},
            {"id": 2, "display_id": 11, "command_name": "ls", "params": "C:\\",
             "status": "submitted", "completed": False, "timestamp": "2026-05-16T10:01:00Z",
             "stdout": "", "stderr": "", "responses": [], "operator": None},
        ]},
    ])
    cfg = {"url": "https://mythic:7443", "token": "tok"}

    with patch.object(httpx, "AsyncClient", return_value=client):
        out = await _mythic_fetch_agent_tasks(cfg, "42", limit=20)

    assert len(out) == 2
    assert out[0]["cmdline"] == "shell whoami"
    assert out[0]["completed"] is True
    assert out[0]["text"] == "user1"
    assert out[0]["user"] == "op1"
    assert out[1]["completed"] is False
    assert out[1]["text"] == ""
