import pytest
import json
from unittest.mock import AsyncMock, MagicMock, patch

from app.ws import (
    _policy_for,
    _redact_payload,
    _resolve_send_msg,
    _scrub_sensitive_keys,
    _scrub_data_keys,
    _get_ws_text,
    _parse_presence_raw,
    ConnectionManager,
    _ENTITY_POLICY,
    _SENSITIVE_KEY_SUBSTRINGS,
    manager,
)
from app.core.permissions import PERM_CREDENTIALS_READ_SECRET


class TestWsManagerSingleton:
    def test_manager_exists(self):
        assert manager is not None
        assert isinstance(manager, ConnectionManager)


class TestWsEntityPolicyCompleteness:
    def test_all_entities_have_valid_policies(self):
        for entity, policy in _ENTITY_POLICY.items():
            assert isinstance(entity, str)
            assert isinstance(policy, dict)
            if "redact" in policy:
                for field, perm in policy["redact"]:
                    assert isinstance(field, str) and field
                    assert isinstance(perm, str) and perm

    def test_network_entities(self):
        assert "network_node" in _ENTITY_POLICY
        assert "network_link" in _ENTITY_POLICY
        assert "network" in _ENTITY_POLICY

    def test_job_entity_has_scrub_keys(self):
        assert _ENTITY_POLICY["job"].get("scrub_keys") is True

    def test_playbook_run_has_scrub_keys(self):
        assert _ENTITY_POLICY["playbook_run"].get("scrub_keys") is True


class TestWsSensitiveKeyPatterns:
    def test_all_patterns_present(self):
        for pattern in ("password", "secret", "api_key", "apikey", "_hash", "credential_text"):
            assert pattern in _SENSITIVE_KEY_SUBSTRINGS


class TestWsRedactJobOutput:
    def test_job_redacts_output_without_secret_perm(self):
        msg = {"entity": "job", "data": {"output": "sensitive_output", "command": "secret_cmd", "status": "done"}}
        policy = _ENTITY_POLICY["job"]
        perms = frozenset(["command_outputs.read"])
        result = _redact_payload(msg, policy, perms)
        assert result["data"]["output"] == ""
        assert result["data"]["command"] == ""

    def test_job_keeps_with_secret_perm(self):
        msg = {"entity": "job", "data": {"output": "out", "command": "cmd"}}
        policy = _ENTITY_POLICY["job"]
        perms = frozenset(["command_outputs.read", PERM_CREDENTIALS_READ_SECRET])
        result = _redact_payload(msg, policy, perms)
        assert result["data"]["output"] == "out"


class TestWsRedactHostActivity:
    def test_redacts_command_and_output(self):
        msg = {"entity": "host_activity", "data": {"command": "secret", "output": "out", "title": "ok"}}
        policy = _ENTITY_POLICY["host_activity"]
        perms = frozenset(["hosts.read"])
        result = _redact_payload(msg, policy, perms)
        assert result["data"]["command"] == ""
        assert result["data"]["output"] == ""
        assert result["data"]["title"] == "ok"


class TestWsScrubNestedJobData:
    def test_scrubs_request_json_password(self):
        data = {"status": "done", "request_json": {"password": "p", "host": "10.0.0.1", "username": "admin"}}
        _scrub_data_keys(data)
        assert data["request_json"]["password"] == ""
        assert data["request_json"]["host"] == "10.0.0.1"


class TestWsConnectionManagerPresence:
    @pytest.mark.asyncio
    async def test_presence_local_fallback(self):
        mgr = ConnectionManager()
        ws = MagicMock()
        ws.accept = AsyncMock()
        mgr._ensure_subscribed = AsyncMock()
        mgr._presence_add = AsyncMock()
        await mgr.connect(ws, "p1", "alice", permissions=frozenset(["hosts.read"]))
        presence = await mgr.get_presence("p1")
        assert len(presence) == 1
        assert presence[0]["name"] == "alice"

    @pytest.mark.asyncio
    async def test_presence_empty_room(self):
        mgr = ConnectionManager()
        presence = await mgr.get_presence("nonexistent")
        assert presence == []


class TestWsBroadcastFlow:
    @pytest.mark.asyncio
    async def test_broadcast_sends_to_all_in_room(self):
        mgr = ConnectionManager()
        sockets = []
        for i in range(3):
            ws = MagicMock()
            ws.accept = AsyncMock()
            ws.send_text = AsyncMock()
            mgr._ensure_subscribed = AsyncMock()
            mgr._presence_add = AsyncMock()
            await mgr.connect(ws, "p1", f"user{i}", permissions=frozenset(["hosts.read"]))
            sockets.append(ws)
        msg = {"entity": "host", "action": "create", "data": {"id": "h1"}}
        await mgr._local_broadcast("p1", msg)
        for ws in sockets:
            ws.send_text.assert_called_once()

    @pytest.mark.asyncio
    async def test_broadcast_skips_no_perm(self):
        mgr = ConnectionManager()
        ws_with_perm = MagicMock()
        ws_with_perm.accept = AsyncMock()
        ws_with_perm.send_text = AsyncMock()
        ws_no_perm = MagicMock()
        ws_no_perm.accept = AsyncMock()
        ws_no_perm.send_text = AsyncMock()
        mgr._ensure_subscribed = AsyncMock()
        mgr._presence_add = AsyncMock()
        await mgr.connect(ws_with_perm, "p1", "u1", permissions=frozenset(["hosts.read"]))
        await mgr.connect(ws_no_perm, "p1", "u2", permissions=frozenset())
        msg = {"entity": "host", "action": "create", "data": {"id": "h1"}}
        await mgr._local_broadcast("p1", msg)
        ws_with_perm.send_text.assert_called_once()
        ws_no_perm.send_text.assert_not_called()
