"""
Tests for permission-aware WebSocket broadcast.

Covers:
  - Recipients missing the entity read permission do not receive the event.
  - Recipients with read but no read_secret receive a redacted payload.
  - Global admin recipients bypass policy entirely.
  - Public events (presence) reach everyone.
  - Entities not in the policy table default to delivery (backwards compat).
"""
from unittest.mock import AsyncMock

import pytest

from app.ws import ConnectionManager


def _ws_mock():
    ws = AsyncMock()
    ws.accept = AsyncMock()
    ws.send_text = AsyncMock()
    return ws


async def _connect(mgr, ws, pid, name, perms=None, admin=False):
    await mgr.connect(ws, pid, name,
                      permissions=frozenset(perms or []),
                      is_global_admin=admin)


@pytest.mark.asyncio
async def test_recipient_without_entity_read_is_skipped():
    mgr = ConnectionManager()
    viewer = _ws_mock()
    editor = _ws_mock()
    await _connect(mgr, viewer, "p1", "viewer", perms={"hosts.read"})  # no credentials.read
    await _connect(mgr, editor, "p1", "editor", perms={"credentials.read"})

    await mgr._local_broadcast("p1", {
        "pid": "p1", "entity": "cred", "action": "create",
        "data": {"id": "c1", "username": "alice", "secret": "p@ss"},
    })

    viewer.send_text.assert_not_called()
    editor.send_text.assert_awaited_once()


@pytest.mark.asyncio
async def test_recipient_with_read_but_no_read_secret_gets_redacted():
    mgr = ConnectionManager()
    viewer = _ws_mock()
    editor = _ws_mock()
    await _connect(mgr, viewer, "p1", "viewer", perms={"credentials.read"})
    await _connect(mgr, editor, "p1", "editor", perms={"credentials.read", "credentials.read_secret"})

    await mgr._local_broadcast("p1", {
        "pid": "p1", "entity": "cred", "action": "create",
        "data": {"id": "c1", "username": "alice", "secret": "p@ss"},
    })

    import json
    viewer_text = viewer.send_text.await_args.args[0]
    editor_text = editor.send_text.await_args.args[0]
    assert json.loads(viewer_text)["data"]["secret"] == ""
    assert json.loads(editor_text)["data"]["secret"] == "p@ss"


@pytest.mark.asyncio
async def test_global_admin_bypasses_policy():
    mgr = ConnectionManager()
    admin = _ws_mock()
    await _connect(mgr, admin, "p1", "admin", perms=set(), admin=True)

    await mgr._local_broadcast("p1", {
        "pid": "p1", "entity": "cred", "action": "create",
        "data": {"id": "c1", "username": "alice", "secret": "p@ss"},
    })

    import json
    admin_text = admin.send_text.await_args.args[0]
    assert json.loads(admin_text)["data"]["secret"] == "p@ss"


@pytest.mark.asyncio
async def test_presence_event_reaches_everyone_regardless_of_perms():
    mgr = ConnectionManager()
    no_perms = _ws_mock()
    await _connect(mgr, no_perms, "p1", "anon", perms=set())

    await mgr._local_broadcast("p1", {"type": "presence", "users": []})

    no_perms.send_text.assert_awaited_once()


@pytest.mark.asyncio
async def test_unknown_entity_delivers_to_all_members():
    """Entities not in the policy table fall through (no breaking-change risk)."""
    mgr = ConnectionManager()
    viewer = _ws_mock()
    await _connect(mgr, viewer, "p1", "viewer", perms=set())

    await mgr._local_broadcast("p1", {
        "pid": "p1", "entity": "some_new_entity", "action": "create",
        "data": {"x": 1},
    })

    viewer.send_text.assert_awaited_once()


@pytest.mark.asyncio
async def test_exclude_websocket_is_skipped():
    mgr = ConnectionManager()
    a = _ws_mock()
    b = _ws_mock()
    await _connect(mgr, a, "p1", "a", perms={"hosts.read"})
    await _connect(mgr, b, "p1", "b", perms={"hosts.read"})

    await mgr._local_broadcast("p1", {
        "pid": "p1", "entity": "host", "action": "update",
        "data": {"id": "h1"},
    }, exclude=a)

    a.send_text.assert_not_called()
    b.send_text.assert_awaited_once()


@pytest.mark.asyncio
async def test_host_event_blocked_for_auditor_without_hosts_read():
    """Auditor role doesn't have hosts.update events, but does have hosts.read,
    so this scenario tests an even-more-restrictive role (e.g. a custom role
    or empty perms)."""
    mgr = ConnectionManager()
    minimal = _ws_mock()
    await _connect(mgr, minimal, "p1", "min", perms={"project.read"})  # no hosts.read

    await mgr._local_broadcast("p1", {
        "pid": "p1", "entity": "host", "action": "create",
        "data": {"id": "h1", "ip": "10.0.0.1"},
    })

    minimal.send_text.assert_not_called()
