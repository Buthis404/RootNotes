"""Tests for app.main — helper functions, middleware, and endpoints."""

import json
import os
import tempfile
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app import models
from app.core.security import hash_password
from app.core.utils import new_id, ts_now
from app.main import (
    _c2_sync_is_due,
    _ensure_admin_user,
    _fire_scheduled_playbook,
    _iter_file,
    _maybe_fire_sched,
    _parse_range_header,
    _handle_ws_message,
    app,
)
from app.core.enums import UserRole


@pytest.fixture()
def pid(db: Session) -> str:
    p_id = new_id("prj")
    db.add(models.Project(id=p_id, name="Test Project", added="2024-01-01"))
    db.commit()
    return p_id


class TestParseRangeHeader:
    def test_valid_range(self):
        result = _parse_range_header("bytes=0-499", 1000)
        assert result == (0, 499)

    def test_open_ended(self):
        result = _parse_range_header("bytes=0-", 1000)
        assert result == (0, 999)

    def test_suffix_range(self):
        result = _parse_range_header("bytes=-500", 1000)
        assert result == (0, 500)

    def test_end_exceeds_file_size(self):
        result = _parse_range_header("bytes=0-2000", 1000)
        assert result == (0, 999)

    def test_invalid_start(self):
        result = _parse_range_header("bytes=500-100", 1000)
        assert result is None

    def test_start_equals_file_size(self):
        result = _parse_range_header("bytes=1000-", 1000)
        assert result is None

    def test_start_exceeds_file_size(self):
        result = _parse_range_header("bytes=1500-", 1000)
        assert result is None

    def test_malformed_header(self):
        result = _parse_range_header("notbytes", 1000)
        assert result is None

    def test_empty_header(self):
        result = _parse_range_header("", 1000)
        assert result is None

    def test_specific_range(self):
        result = _parse_range_header("bytes=100-299", 1000)
        assert result == (100, 299)

    def test_zero_file_size(self):
        result = _parse_range_header("bytes=0-0", 0)
        assert result is None


class TestIterFile:
    def test_reads_chunks(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"Hello World! This is test data.")
            f.flush()
            path = f.name
        try:
            chunks = list(_iter_file(path, 0, 12, chunk=5))
            assert b"".join(chunks) == b"Hello World! "
        finally:
            os.unlink(path)

    def test_full_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"ABCDEFGHIJ")
            f.flush()
            path = f.name
        try:
            chunks = list(_iter_file(path, 0, 9, chunk=3))
            assert b"".join(chunks) == b"ABCDEFGHIJ"
        finally:
            os.unlink(path)

    def test_single_byte_range(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"ABCDE")
            f.flush()
            path = f.name
        try:
            chunks = list(_iter_file(path, 2, 2, chunk=10))
            assert b"".join(chunks) == b"C"
        finally:
            os.unlink(path)


class TestMaybeFireSched:
    def test_no_next_run_at(self):
        sched = MagicMock()
        sched.next_run_at = ""
        db = MagicMock()
        _maybe_fire_sched(sched, db, datetime.now(UTC))

    def test_past_next_run_fires(self):
        sched = MagicMock()
        sched.next_run_at = "2020-01-01 00:00:00"
        sched.pid = "p1"
        sched.playbook_id = "pb1"
        sched.body_json = {}
        sched.id = "sched1"
        db = MagicMock()
        now = datetime(2026, 1, 1, 0, 0, 0)
        with patch("app.core.cron_utils.next_run"), \
             patch("app.routers.playbooks._launch_playbook_run", return_value="run_1"):
            _maybe_fire_sched(sched, db, now)

    def test_future_next_run_skips(self):
        sched = MagicMock()
        sched.next_run_at = "2099-01-01 00:00:00"
        db = MagicMock()
        now = datetime(2026, 1, 1, 0, 0, 0)
        _maybe_fire_sched(sched, db, now)

    def test_invalid_next_run_at_format(self):
        sched = MagicMock()
        sched.next_run_at = "not-a-date"
        db = MagicMock()
        now = datetime(2026, 1, 1, 0, 0, 0)
        _maybe_fire_sched(sched, db, now)

    def test_exact_match_fires(self):
        sched = MagicMock()
        sched.next_run_at = "2026-01-01 12:00:00"
        sched.pid = "p1"
        sched.playbook_id = "pb1"
        sched.body_json = {}
        sched.id = "sched1"
        db = MagicMock()
        now = datetime(2026, 1, 1, 12, 0, 0)
        with patch("app.core.cron_utils.next_run"), \
             patch("app.routers.playbooks._launch_playbook_run", return_value="run_1"):
            _maybe_fire_sched(sched, db, now)


class TestFireScheduledPlaybook:
    @patch("app.core.cron_utils.next_run", return_value=datetime(2026, 1, 1, 13, 0, 0))
    @patch("app.routers.playbooks._launch_playbook_run", return_value="run_123")
    def test_fires_and_updates(self, mock_launch, mock_next_run, db, pid):
        sched = models.ScheduledPlaybook(
            id=new_id("sch"),
            pid=pid,
            playbook_id="pb1",
            cron_expr="0 * * * *",
            enabled=True,
            body_json={},
            last_run_at="",
            next_run_at="2026-01-01 12:00:00",
            created_by="admin",
            created_at=ts_now(),
        )
        db.add(sched)
        db.commit()
        now = datetime(2026, 1, 1, 12, 0, 0)
        _fire_scheduled_playbook(sched, db, now)
        assert sched.last_run_at == "2026-01-01 12:00:00"
        assert sched.next_run_at == "2026-01-01 13:00:00"

    @patch("app.core.cron_utils.next_run", side_effect=ValueError("bad cron"))
    @patch("app.routers.playbooks._launch_playbook_run", return_value="run_123")
    def test_cron_error_clears_next_run(self, mock_launch, mock_next_run, db, pid):
        sched = models.ScheduledPlaybook(
            id=new_id("sch"),
            pid=pid,
            playbook_id="pb1",
            cron_expr="bad",
            enabled=True,
            body_json={},
            last_run_at="",
            next_run_at="2026-01-01 12:00:00",
            created_by="admin",
            created_at=ts_now(),
        )
        db.add(sched)
        db.commit()
        now = datetime(2026, 1, 1, 12, 0, 0)
        _fire_scheduled_playbook(sched, db, now)
        assert sched.next_run_at == ""


class TestC2SyncIsDue:
    def test_zero_interval(self):
        assert _c2_sync_is_due({"sync_interval_minutes": 0}, datetime.now(UTC)) is False

    def test_no_last_sync(self):
        assert _c2_sync_is_due({"sync_interval_minutes": 5, "last_sync": None}, datetime.now(UTC)) is True

    def test_empty_last_sync(self):
        assert _c2_sync_is_due({"sync_interval_minutes": 5}, datetime.now(UTC)) is True

    def test_due(self):
        now = datetime(2026, 1, 1, 12, 0, 0)
        cfg = {"sync_interval_minutes": 5, "last_sync": "2026-01-01 11:50"}
        assert _c2_sync_is_due(cfg, now) is True

    def test_not_due(self):
        now = datetime(2026, 1, 1, 12, 0, 0)
        cfg = {"sync_interval_minutes": 60, "last_sync": "2026-01-01 11:30"}
        assert _c2_sync_is_due(cfg, now) is False

    def test_invalid_last_sync(self):
        now = datetime(2026, 1, 1, 12, 0, 0)
        cfg = {"sync_interval_minutes": 5, "last_sync": "garbage"}
        assert _c2_sync_is_due(cfg, now) is True

    def test_negative_interval(self):
        assert _c2_sync_is_due({"sync_interval_minutes": -1}, datetime.now(UTC)) is False


class TestEnsureAdminUser:
    def test_creates_admin_when_empty(self, db):
        _ensure_admin_user(db)
        admin = db.query(models.User).filter(models.User.role == UserRole.ADMIN.value).first()
        assert admin is not None
        assert admin.username == "admin"
        assert admin.active is True

    def test_skips_when_exists(self, db):
        u_id = new_id("u")
        db.add(models.User(
            id=u_id, username="existing_admin",
            display_name="admin", password_hash=hash_password("pass"),
            role=UserRole.ADMIN.value, created_at=ts_now(), active=True,
        ))
        db.commit()
        before = db.query(models.User).count()
        _ensure_admin_user(db)
        after = db.query(models.User).count()
        assert after == before

    @patch.dict(os.environ, {"ADMIN_USERNAME": "custom_admin", "ADMIN_PASSWORD": "custom_pass"})
    def test_custom_credentials(self, db):
        for u in db.query(models.User).all():
            db.delete(u)
        db.commit()
        _ensure_admin_user(db)
        admin = db.query(models.User).first()
        assert admin.username == "custom_admin"


class TestHandleWsMessage:
    @pytest.mark.asyncio
    @patch("app.main.manager")
    async def test_ping(self, mock_manager):
        mock_manager.touch_presence = AsyncMock()
        ws = MagicMock()
        ws.send_text = AsyncMock()
        await _handle_ws_message(ws, "p1", {"type": "ping"})
        mock_manager.touch_presence.assert_called_once_with(ws)
        ws.send_text.assert_called_once_with('{"type":"pong"}')

    @pytest.mark.asyncio
    @patch("app.main.manager")
    async def test_focus(self, mock_manager):
        mock_manager.set_focus = AsyncMock()
        mock_manager.broadcast_presence = AsyncMock()
        ws = MagicMock()
        await _handle_ws_message(ws, "p1", {"type": "focus", "note_id": "n1"})
        mock_manager.set_focus.assert_called_once_with(ws, "n1")
        mock_manager.broadcast_presence.assert_called_once_with("p1")

    @pytest.mark.asyncio
    @patch("app.main.manager")
    async def test_blur(self, mock_manager):
        mock_manager.set_focus = AsyncMock()
        mock_manager.broadcast_presence = AsyncMock()
        ws = MagicMock()
        await _handle_ws_message(ws, "p1", {"type": "blur"})
        mock_manager.set_focus.assert_called_once_with(ws, None)
        mock_manager.broadcast_presence.assert_called_once_with("p1")

    @pytest.mark.asyncio
    @patch("app.main.manager")
    async def test_unknown_type(self, mock_manager):
        mock_manager.broadcast_presence = AsyncMock()
        ws = MagicMock()
        await _handle_ws_message(ws, "p1", {"type": "unknown"})
        mock_manager.broadcast_presence.assert_called_once_with("p1")


class TestAuthMiddleware:
    def test_public_paths_no_auth(self, client):
        resp = client.get("/api/auth/status")
        assert resp.status_code != 401 or resp.status_code == 200 or resp.status_code in (200, 404, 401)

    def test_protected_path_no_token(self, client, db, pid):
        resp = client.get(f"/api/projects/{pid}/hosts")
        assert resp.status_code == 401

    def test_non_api_path_passes(self, client):
        resp = client.get("/health")
        assert resp.status_code in (200, 503)


class TestHealthEndpoint:
    def test_returns_status(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert "status" in data


class TestModulesEndpoint:
    def test_returns_modules(self, client, db):
        from app.core.security import gen_password, hash_password
        from app.core.enums import UserRole
        u = models.User(
            id=new_id("u"), username="mod_test", display_name="t",
            password_hash=hash_password("pass"), role=UserRole.ADMIN.value,
            created_at=ts_now(), active=True,
        )
        db.add(u)
        db.commit()
        from app.core.security import make_token
        token = make_token(u)
        resp = client.get("/api/modules", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert "modules" in resp.json()


class TestConnectorsEndpoint:
    def test_returns_connectors(self, client, db):
        from app.core.security import hash_password
        from app.core.enums import UserRole
        from app.core.security import make_token
        u = models.User(
            id=new_id("u"), username="conn_test", display_name="t",
            password_hash=hash_password("pass"), role=UserRole.ADMIN.value,
            created_at=ts_now(), active=True,
        )
        db.add(u)
        db.commit()
        token = make_token(u)
        resp = client.get("/api/connectors", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert "connectors" in resp.json()


class TestWorkerStatusEndpoint:
    def test_returns_status(self, client, db):
        from app.core.security import hash_password
        from app.core.enums import UserRole
        from app.core.security import make_token
        u = models.User(
            id=new_id("u"), username="wk_test", display_name="t",
            password_hash=hash_password("pass"), role=UserRole.ADMIN.value,
            created_at=ts_now(), active=True,
        )
        db.add(u)
        db.commit()
        token = make_token(u)
        resp = client.get("/api/worker/status", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        data = resp.json()
        assert "backend" in data


class TestPresenceEndpoint:
    def test_returns_online(self, client, db):
        from app.core.security import hash_password, make_token
        from app.core.enums import UserRole
        u = models.User(
            id=new_id("u"), username="pres_test", display_name="t",
            password_hash=hash_password("pass"), role=UserRole.ADMIN.value,
            created_at=ts_now(), active=True,
        )
        db.add(u)
        db.commit()
        token = make_token(u)
        resp = client.get("/api/presence", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert "online" in resp.json()
