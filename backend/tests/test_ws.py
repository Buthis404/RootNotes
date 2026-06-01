"""Consolidated tests for test_ws (merged variant files)."""

# ════════ from test_ws.py ════════
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import WebSocket

from app.core.permissions import PERM_CREDENTIALS_READ_SECRET
from app.ws import (
    _ENTITY_POLICY,
    _get_ws_text,
    _parse_presence_raw,
    _policy_for,
    _redact_payload,
    _resolve_send_msg,
    _scrub_data_keys,
    _scrub_sensitive_keys,
    ConnectionManager,
    _SENSITIVE_KEY_SUBSTRINGS,
)


class TestPolicyFor:
    def test_presence_message(self):
        msg = {"type": "presence", "users": []}
        policy = _policy_for(msg)
        assert policy == {"public": True}

    def test_known_entity(self):
        msg = {"entity": "cred", "action": "create", "data": {}}
        policy = _policy_for(msg)
        assert policy is not None
        assert "read" in policy

    def test_unknown_entity(self):
        msg = {"entity": "custom_thing", "action": "create", "data": {}}
        policy = _policy_for(msg)
        assert policy is None

    def test_empty_entity(self):
        msg = {"entity": "", "action": "create", "data": {}}
        policy = _policy_for(msg)
        assert policy is None

    def test_host_entity(self):
        msg = {"entity": "host", "action": "upsert", "data": {}}
        policy = _policy_for(msg)
        assert policy is not None
        assert policy.get("read") == "hosts.read"

    def test_no_entity_key(self):
        msg = {"action": "create", "data": {}}
        policy = _policy_for(msg)
        assert policy is None

    def test_all_entity_policies_valid(self):
        for entity, policy in _ENTITY_POLICY.items():
            assert isinstance(policy, dict)
            if "redact" in policy:
                for field, perm in policy["redact"]:
                    assert isinstance(field, str)
                    assert isinstance(perm, str)


class TestScrubSensitiveKeys:
    def test_scrubs_password(self):
        data = {"password": "secret123", "name": "test"}
        result = _scrub_sensitive_keys(data)
        assert result["password"] == ""
        assert result["name"] == "test"

    def test_scrubs_nested(self):
        data = {"config": {"api_key": "abc123", "port": 8080}}
        result = _scrub_sensitive_keys(data)
        assert result["config"]["api_key"] == ""
        assert result["config"]["port"] == 8080

    def test_scrubs_list(self):
        data = [{"password": "a"}, {"password": "b"}]
        result = _scrub_sensitive_keys(data)
        assert result[0]["password"] == ""
        assert result[1]["password"] == ""

    def test_passes_through_primitives(self):
        assert _scrub_sensitive_keys("hello") == "hello"
        assert _scrub_sensitive_keys(42) == 42
        assert _scrub_sensitive_keys(None) is None

    def test_scrubs_secret(self):
        data = {"my_secret": "hidden"}
        result = _scrub_sensitive_keys(data)
        assert result["my_secret"] == ""

    def test_scrubs_apikey(self):
        data = {"x_apikey": "key123"}
        result = _scrub_sensitive_keys(data)
        assert result["x_apikey"] == ""

    def test_scrubs_hash(self):
        data = {"nt_hash": "AADM123"}
        result = _scrub_sensitive_keys(data)
        assert result["nt_hash"] == ""

    def test_scrubs_credential_text(self):
        data = {"credential_text": "pass"}
        result = _scrub_sensitive_keys(data)
        assert result["credential_text"] == ""

    def test_empty_dict(self):
        assert _scrub_sensitive_keys({}) == {}

    def test_empty_list(self):
        assert _scrub_sensitive_keys([]) == []

    def test_deeply_nested(self):
        data = {"level1": {"level2": {"password": "deep"}}}
        result = _scrub_sensitive_keys(data)
        assert result["level1"]["level2"]["password"] == ""

    def test_preserves_non_sensitive(self):
        data = {"username": "admin", "port": 22, "enabled": True}
        result = _scrub_sensitive_keys(data)
        assert result == {"username": "admin", "port": 22, "enabled": True}


class TestScrubDataKeys:
    def test_scrubs_top_level(self):
        data = {"password": "secret", "name": "test"}
        _scrub_data_keys(data)
        assert data["password"] == ""
        assert data["name"] == "test"

    def test_scrubs_nested_dict(self):
        data = {"config": {"api_key": "abc", "port": 80}}
        _scrub_data_keys(data)
        assert data["config"]["api_key"] == ""
        assert data["config"]["port"] == 80

    def test_scrubs_nested_list(self):
        data = {"items": [{"password": "x"}, {"password": "y"}]}
        _scrub_data_keys(data)
        assert data["items"][0]["password"] == ""
        assert data["items"][1]["password"] == ""


class TestRedactPayload:
    def test_no_redaction_needed(self):
        msg = {"entity": "cred", "data": {"username": "admin"}}
        policy = _ENTITY_POLICY["cred"]
        perms = frozenset(["credentials.read", PERM_CREDENTIALS_READ_SECRET])
        result = _redact_payload(msg, policy, perms)
        assert result == msg

    def test_redacts_secret_field(self):
        msg = {"entity": "cred", "data": {"username": "admin", "secret": "s3cret"}}
        policy = _ENTITY_POLICY["cred"]
        perms = frozenset(["credentials.read"])
        result = _redact_payload(msg, policy, perms)
        assert result["data"]["secret"] == ""
        assert result["data"]["username"] == "admin"

    def test_no_data_key(self):
        msg = {"entity": "cred", "action": "create"}
        policy = _ENTITY_POLICY["cred"]
        perms = frozenset()
        result = _redact_payload(msg, policy, perms)
        assert result == msg

    def test_data_not_dict(self):
        msg = {"entity": "cred", "data": "string"}
        policy = _ENTITY_POLICY["cred"]
        perms = frozenset()
        result = _redact_payload(msg, policy, perms)
        assert result == msg

    def test_host_activity_redaction(self):
        msg = {
            "entity": "host_activity",
            "data": {"command": "secret_cmd", "output": "secret_out", "title": "ok"},
        }
        policy = _ENTITY_POLICY["host_activity"]
        perms = frozenset(["hosts.read"])
        result = _redact_payload(msg, policy, perms)
        assert result["data"]["command"] == ""
        assert result["data"]["output"] == ""
        assert result["data"]["title"] == "ok"

    def test_job_scrub_keys(self):
        msg = {
            "entity": "job",
            "data": {"status": "done", "request_json": {"password": "p", "host": "10.0.0.1"}},
        }
        policy = _ENTITY_POLICY["job"]
        perms = frozenset(["command_outputs.read"])
        result = _redact_payload(msg, policy, perms)
        assert result["data"]["request_json"]["password"] == ""

    def test_playbook_run_scrub(self):
        msg = {
            "entity": "playbook_run",
            "data": {"request_json": {"password": "p"}},
        }
        policy = _ENTITY_POLICY["playbook_run"]
        perms = frozenset(["credentials.read"])
        result = _redact_payload(msg, policy, perms)
        assert result["data"]["request_json"] == ""


class TestResolveSendMsg:
    def test_no_policy_returns_msg(self):
        msg = {"entity": "custom", "data": {}}
        result = _resolve_send_msg(msg, None, frozenset(), False)
        assert result == msg

    def test_public_policy(self):
        msg = {"type": "presence", "users": []}
        policy = {"public": True}
        result = _resolve_send_msg(msg, policy, frozenset(), False)
        assert result == msg

    def test_admin_bypass(self):
        msg = {"entity": "cred", "data": {"secret": "s"}}
        policy = _ENTITY_POLICY["cred"]
        result = _resolve_send_msg(msg, policy, frozenset(), True)
        assert result == msg

    def test_no_permission_returns_none(self):
        msg = {"entity": "cred", "data": {}}
        policy = _ENTITY_POLICY["cred"]
        result = _resolve_send_msg(msg, policy, frozenset(), False)
        assert result is None

    def test_has_permission(self):
        msg = {"entity": "cred", "data": {"username": "admin", "secret": "s"}}
        policy = _ENTITY_POLICY["cred"]
        perms = frozenset(["credentials.read", PERM_CREDENTIALS_READ_SECRET])
        result = _resolve_send_msg(msg, policy, perms, False)
        assert result is not None
        assert result["data"]["secret"] == "s"

    def test_has_read_but_not_secret(self):
        msg = {"entity": "cred", "data": {"username": "admin", "secret": "s"}}
        policy = _ENTITY_POLICY["cred"]
        perms = frozenset(["credentials.read"])
        result = _resolve_send_msg(msg, policy, perms, False)
        assert result is not None
        assert result["data"]["secret"] == ""


class TestGetWsText:
    def test_same_msg_uses_cache(self):
        msg = {"type": "test", "data": 1}
        cache = [None]
        text1 = _get_ws_text(msg, msg, cache)
        assert cache[0] is not None
        text2 = _get_ws_text(msg, msg, cache)
        assert text1 == text2

    def test_different_msg_no_cache(self):
        msg = {"type": "test"}
        send_msg = {"type": "test", "redacted": True}
        cache = [None]
        text = _get_ws_text(send_msg, msg, cache)
        assert json.loads(text) == send_msg

    def test_cache_filled(self):
        msg = {"type": "test", "value": 42}
        cache = [None]
        _get_ws_text(msg, msg, cache)
        assert cache[0] is not None
        assert json.loads(cache[0]) == msg

    def test_empty_cache(self):
        msg = {"a": 1}
        cache = [None]
        result = _get_ws_text(msg, msg, cache)
        assert json.loads(result) == msg


class TestParsePresenceRaw:
    def test_valid_entries(self):
        raw = {
            "conn1": json.dumps({"name": "alice", "note_id": None, "last_seen": time.time()}),
            "conn2": json.dumps({"name": "bob", "note_id": "n1", "last_seen": time.time()}),
        }
        result, stale = _parse_presence_raw(raw, time.time() - 100)
        assert len(result) == 2
        assert len(stale) == 0
        names = {r["name"] for r in result}
        assert names == {"alice", "bob"}

    def test_stale_entries(self):
        old_time = time.time() - 200
        raw = {
            "conn1": json.dumps({"name": "alice", "note_id": None, "last_seen": old_time}),
        }
        result, stale = _parse_presence_raw(raw, time.time() - 90)
        assert len(result) == 0
        assert "conn1" in stale

    def test_invalid_json(self):
        raw = {"conn1": "not-json"}
        result, stale = _parse_presence_raw(raw, time.time() - 100)
        assert len(result) == 0
        assert "conn1" in stale

    def test_missing_last_seen(self):
        raw = {
            "conn1": json.dumps({"name": "alice", "note_id": None}),
        }
        result, stale = _parse_presence_raw(raw, time.time() - 100)
        assert len(result) == 1

    def test_zero_last_seen(self):
        raw = {
            "conn1": json.dumps({"name": "alice", "note_id": None, "last_seen": 0}),
        }
        result, stale = _parse_presence_raw(raw, time.time() - 100)
        assert len(result) == 1

    def test_empty_raw(self):
        result, stale = _parse_presence_raw({}, time.time())
        assert result == []
        assert stale == []

    def test_strips_last_seen_from_output(self):
        raw = {
            "conn1": json.dumps({"name": "alice", "note_id": "n1", "last_seen": time.time()}),
        }
        result, _ = _parse_presence_raw(raw, time.time() - 100)
        assert "last_seen" not in result[0]


class TestConnectionManager:
    def test_init(self):
        mgr = ConnectionManager()
        assert mgr._rooms == {}
        assert mgr._users == {}
        assert mgr._redis is None

    def test_get_all_online_empty(self):
        mgr = ConnectionManager()
        assert mgr.get_all_online() == []

    def test_get_all_online(self):
        mgr = ConnectionManager()
        ws1 = MagicMock(spec=WebSocket)
        ws2 = MagicMock(spec=WebSocket)
        mgr._users[ws1] = {"name": "alice", "pid": "p1"}
        mgr._users[ws2] = {"name": "bob", "pid": "p1"}
        online = mgr.get_all_online()
        assert set(online) == {"alice", "bob"}

    def test_get_all_online_dedup(self):
        mgr = ConnectionManager()
        ws1 = MagicMock(spec=WebSocket)
        ws2 = MagicMock(spec=WebSocket)
        mgr._users[ws1] = {"name": "alice", "pid": "p1"}
        mgr._users[ws2] = {"name": "alice", "pid": "p2"}
        online = mgr.get_all_online()
        assert online == ["alice"]

    @pytest.mark.asyncio
    async def test_connect(self):
        mgr = ConnectionManager()
        ws = MagicMock(spec=WebSocket)
        ws.accept = AsyncMock()
        mgr._ensure_subscribed = AsyncMock()
        mgr._presence_add = AsyncMock()
        await mgr.connect(ws, "p1", "alice")
        assert ws in mgr._users
        assert ws in mgr._rooms.get("p1", set())
        assert mgr._users[ws]["name"] == "alice"
        assert mgr._users[ws]["permissions"] == frozenset()

    @pytest.mark.asyncio
    async def test_connect_with_permissions(self):
        mgr = ConnectionManager()
        ws = MagicMock(spec=WebSocket)
        ws.accept = AsyncMock()
        mgr._ensure_subscribed = AsyncMock()
        mgr._presence_add = AsyncMock()
        perms = frozenset(["hosts.read", "credentials.read"])
        await mgr.connect(ws, "p1", "alice", permissions=perms, is_global_admin=True)
        assert mgr._users[ws]["permissions"] == perms
        assert mgr._users[ws]["is_global_admin"] is True

    @pytest.mark.asyncio
    async def test_connect_default_name(self):
        mgr = ConnectionManager()
        ws = MagicMock(spec=WebSocket)
        ws.accept = AsyncMock()
        mgr._ensure_subscribed = AsyncMock()
        mgr._presence_add = AsyncMock()
        await mgr.connect(ws, "p1", "")
        assert mgr._users[ws]["name"] == "Anonymous"

    @pytest.mark.asyncio
    async def test_disconnect(self):
        mgr = ConnectionManager()
        ws = MagicMock(spec=WebSocket)
        ws.accept = AsyncMock()
        mgr._ensure_subscribed = AsyncMock()
        mgr._presence_add = AsyncMock()
        mgr._presence_remove = AsyncMock()
        await mgr.connect(ws, "p1", "alice")
        await mgr.disconnect(ws, "p1")
        assert ws not in mgr._users
        assert ws not in mgr._rooms.get("p1", set())

    @pytest.mark.asyncio
    async def test_disconnect_removes_empty_room(self):
        mgr = ConnectionManager()
        ws = MagicMock(spec=WebSocket)
        ws.accept = AsyncMock()
        mgr._ensure_subscribed = AsyncMock()
        mgr._presence_add = AsyncMock()
        mgr._presence_remove = AsyncMock()
        await mgr.connect(ws, "p1", "alice")
        await mgr.disconnect(ws, "p1")
        assert "p1" not in mgr._rooms

    @pytest.mark.asyncio
    async def test_disconnect_keeps_room_with_others(self):
        mgr = ConnectionManager()
        ws1 = MagicMock(spec=WebSocket)
        ws2 = MagicMock(spec=WebSocket)
        for ws in (ws1, ws2):
            ws.accept = AsyncMock()
        mgr._ensure_subscribed = AsyncMock()
        mgr._presence_add = AsyncMock()
        mgr._presence_remove = AsyncMock()
        await mgr.connect(ws1, "p1", "alice")
        await mgr.connect(ws2, "p1", "bob")
        await mgr.disconnect(ws1, "p1")
        assert "p1" in mgr._rooms
        assert ws2 in mgr._rooms["p1"]

    @pytest.mark.asyncio
    async def test_set_focus(self):
        mgr = ConnectionManager()
        ws = MagicMock(spec=WebSocket)
        ws.accept = AsyncMock()
        mgr._ensure_subscribed = AsyncMock()
        mgr._presence_add = AsyncMock()
        await mgr.connect(ws, "p1", "alice")
        await mgr.set_focus(ws, "note_1")
        assert mgr._users[ws]["note_id"] == "note_1"

    @pytest.mark.asyncio
    async def test_set_focus_none(self):
        mgr = ConnectionManager()
        ws = MagicMock(spec=WebSocket)
        ws.accept = AsyncMock()
        mgr._ensure_subscribed = AsyncMock()
        mgr._presence_add = AsyncMock()
        await mgr.connect(ws, "p1", "alice")
        await mgr.set_focus(ws, "note_1")
        await mgr.set_focus(ws, None)
        assert mgr._users[ws]["note_id"] is None

    @pytest.mark.asyncio
    async def test_set_focus_unknown_ws(self):
        mgr = ConnectionManager()
        ws = MagicMock(spec=WebSocket)
        await mgr.set_focus(ws, "note_1")

    @pytest.mark.asyncio
    async def test_get_presence_local(self):
        mgr = ConnectionManager()
        ws = MagicMock(spec=WebSocket)
        ws.accept = AsyncMock()
        mgr._ensure_subscribed = AsyncMock()
        mgr._presence_add = AsyncMock()
        await mgr.connect(ws, "p1", "alice")
        presence = await mgr.get_presence("p1")
        assert len(presence) == 1
        assert presence[0]["name"] == "alice"

    @pytest.mark.asyncio
    async def test_get_presence_filters_by_pid(self):
        mgr = ConnectionManager()
        ws1 = MagicMock(spec=WebSocket)
        ws2 = MagicMock(spec=WebSocket)
        for ws in (ws1, ws2):
            ws.accept = AsyncMock()
        mgr._ensure_subscribed = AsyncMock()
        mgr._presence_add = AsyncMock()
        await mgr.connect(ws1, "p1", "alice")
        await mgr.connect(ws2, "p2", "bob")
        presence = await mgr.get_presence("p1")
        assert len(presence) == 1
        assert presence[0]["name"] == "alice"

    @pytest.mark.asyncio
    async def test_broadcast_local(self):
        mgr = ConnectionManager()
        ws1 = MagicMock(spec=WebSocket)
        ws2 = MagicMock(spec=WebSocket)
        for ws in (ws1, ws2):
            ws.accept = AsyncMock()
            ws.send_text = AsyncMock()
        mgr._ensure_subscribed = AsyncMock()
        mgr._presence_add = AsyncMock()
        await mgr.connect(ws1, "p1", "alice", permissions=frozenset(["hosts.read"]))
        await mgr.connect(ws2, "p1", "bob", permissions=frozenset(["hosts.read"]))
        msg = {"entity": "host", "action": "create", "data": {"id": "h1"}}
        await mgr._local_broadcast("p1", msg)
        ws1.send_text.assert_called_once()
        ws2.send_text.assert_called_once()

    @pytest.mark.asyncio
    async def test_broadcast_excludes(self):
        mgr = ConnectionManager()
        ws1 = MagicMock(spec=WebSocket)
        ws2 = MagicMock(spec=WebSocket)
        for ws in (ws1, ws2):
            ws.accept = AsyncMock()
            ws.send_text = AsyncMock()
        mgr._ensure_subscribed = AsyncMock()
        mgr._presence_add = AsyncMock()
        await mgr.connect(ws1, "p1", "alice", permissions=frozenset(["hosts.read"]))
        await mgr.connect(ws2, "p1", "bob", permissions=frozenset(["hosts.read"]))
        msg = {"entity": "host", "action": "create", "data": {"id": "h1"}}
        await mgr._local_broadcast("p1", msg, exclude=ws1)
        ws1.send_text.assert_not_called()
        ws2.send_text.assert_called_once()

    @pytest.mark.asyncio
    async def test_broadcast_filters_by_permission(self):
        mgr = ConnectionManager()
        ws1 = MagicMock(spec=WebSocket)
        ws2 = MagicMock(spec=WebSocket)
        for ws in (ws1, ws2):
            ws.accept = AsyncMock()
            ws.send_text = AsyncMock()
        mgr._ensure_subscribed = AsyncMock()
        mgr._presence_add = AsyncMock()
        await mgr.connect(ws1, "p1", "alice", permissions=frozenset(["hosts.read"]))
        await mgr.connect(ws2, "p1", "bob", permissions=frozenset())
        msg = {"entity": "host", "action": "create", "data": {"id": "h1"}}
        await mgr._local_broadcast("p1", msg)
        ws1.send_text.assert_called_once()
        ws2.send_text.assert_not_called()

    @pytest.mark.asyncio
    async def test_broadcast_admin_bypasses_policy(self):
        mgr = ConnectionManager()
        ws = MagicMock(spec=WebSocket)
        ws.accept = AsyncMock()
        ws.send_text = AsyncMock()
        mgr._ensure_subscribed = AsyncMock()
        mgr._presence_add = AsyncMock()
        await mgr.connect(ws, "p1", "admin", permissions=frozenset(), is_global_admin=True)
        msg = {"entity": "cred", "action": "create", "data": {"secret": "s"}}
        await mgr._local_broadcast("p1", msg)
        ws.send_text.assert_called_once()
        sent = json.loads(ws.send_text.call_args[0][0])
        assert sent["data"]["secret"] == "s"

    @pytest.mark.asyncio
    async def test_broadcast_removes_dead_ws(self):
        mgr = ConnectionManager()
        ws = MagicMock(spec=WebSocket)
        ws.accept = AsyncMock()
        ws.send_text = AsyncMock(side_effect=Exception("dead"))
        mgr._ensure_subscribed = AsyncMock()
        mgr._presence_add = AsyncMock()
        await mgr.connect(ws, "p1", "alice", permissions=frozenset(["hosts.read"]))
        msg = {"entity": "host", "action": "create", "data": {}}
        await mgr._local_broadcast("p1", msg)
        assert ws not in mgr._rooms.get("p1", set())

    @pytest.mark.asyncio
    @patch("app.ws._get_redis", return_value=None)
    async def test_startup_no_redis(self, mock_redis):
        mgr = ConnectionManager()
        await mgr.startup()
        assert mgr._redis is None

    @pytest.mark.asyncio
    async def test_shutdown_no_task(self):
        mgr = ConnectionManager()
        await mgr.shutdown()

    @pytest.mark.asyncio
    async def test_touch_presence(self):
        mgr = ConnectionManager()
        ws = MagicMock(spec=WebSocket)
        ws.accept = AsyncMock()
        mgr._ensure_subscribed = AsyncMock()
        mgr._presence_add = AsyncMock()
        await mgr.connect(ws, "p1", "alice")
        await mgr.set_focus(ws, "n1")
        await mgr.touch_presence(ws)
        mgr._presence_add.assert_called()

    @pytest.mark.asyncio
    async def test_touch_presence_unknown_ws(self):
        mgr = ConnectionManager()
        ws = MagicMock(spec=WebSocket)
        await mgr.touch_presence(ws)

    @pytest.mark.asyncio
    async def test_broadcast_presence_uses_broadcast(self):
        mgr = ConnectionManager()
        mgr.get_presence = AsyncMock(return_value=[{"name": "alice"}])
        mgr.broadcast = AsyncMock()
        await mgr.broadcast_presence("p1")
        mgr.broadcast.assert_called_once()
        msg = mgr.broadcast.call_args[0][1]
        assert msg["type"] == "presence"
        assert len(msg["users"]) == 1


class TestSensitiveKeySubstrings:
    def test_contains_expected_patterns(self):
        assert "password" in _SENSITIVE_KEY_SUBSTRINGS
        assert "secret" in _SENSITIVE_KEY_SUBSTRINGS
        assert "api_key" in _SENSITIVE_KEY_SUBSTRINGS
        assert "apikey" in _SENSITIVE_KEY_SUBSTRINGS
        assert "_hash" in _SENSITIVE_KEY_SUBSTRINGS
        assert "credential_text" in _SENSITIVE_KEY_SUBSTRINGS


# ════════ from test_ws_extended.py ════════
import json
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import WebSocket

from app.ws import ConnectionManager


class TestConnectionManagerBroadcastPresence:
    @pytest.mark.asyncio
    async def test_broadcast_presence(self):
        mgr = ConnectionManager()
        mgr.get_presence = AsyncMock(return_value=[{"name": "alice"}])
        mgr.broadcast = AsyncMock()
        await mgr.broadcast_presence("p1")
        mgr.broadcast.assert_called_once()
        msg = mgr.broadcast.call_args[0][1]
        assert msg["type"] == "presence"


class TestConnectionManagerEnsureSubscribed:
    @pytest.mark.asyncio
    async def test_no_redis(self):
        mgr = ConnectionManager()
        mgr._redis = None
        await mgr._ensure_subscribed("p1")

    @pytest.mark.asyncio
    async def test_with_redis(self):
        mgr = ConnectionManager()
        mgr._redis = MagicMock()
        await mgr._ensure_subscribed("p1")
        assert "p1" in mgr._subscribed_pids


class TestConnectionManagerRedisListener:
    @pytest.mark.asyncio
    async def test_listener_no_redis(self):
        mgr = ConnectionManager()
        mgr._redis = None
        await mgr._redis_listener()


class TestConnectionManagerPresenceRedis:
    @pytest.mark.asyncio
    async def test_presence_add_redis(self):
        mgr = ConnectionManager()
        mock_redis = AsyncMock()
        mgr._redis = mock_redis
        await mgr._presence_add("p1", "c1", "alice", None)
        mock_redis.hset.assert_called_once()

    @pytest.mark.asyncio
    async def test_presence_remove_redis(self):
        mgr = ConnectionManager()
        mock_redis = AsyncMock()
        mgr._redis = mock_redis
        await mgr._presence_remove("p1", "c1")
        mock_redis.hdel.assert_called_once()

    @pytest.mark.asyncio
    async def test_presence_add_no_redis(self):
        mgr = ConnectionManager()
        mgr._redis = None
        await mgr._presence_add("p1", "c1", "alice", None)

    @pytest.mark.asyncio
    async def test_presence_remove_no_redis(self):
        mgr = ConnectionManager()
        mgr._redis = None
        await mgr._presence_remove("p1", "c1")


class TestConnectionManagerShutdown:
    @pytest.mark.asyncio
    async def test_shutdown_with_redis(self):
        mgr = ConnectionManager()
        mgr._redis = AsyncMock()
        mgr._subscriber_task = None
        await mgr.shutdown()
        mgr._redis.aclose.assert_called_once()

    @pytest.mark.asyncio
    async def test_shutdown_with_task(self):
        mgr = ConnectionManager()
        mgr._redis = None
        mock_task = MagicMock()
        mock_task.cancel = MagicMock()
        mgr._subscriber_task = mock_task
        await mgr.shutdown()
        mock_task.cancel.assert_called_once()


# ════════ from test_ws_final.py ════════
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
