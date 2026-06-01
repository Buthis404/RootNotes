"""Unit tests for app.core.events — event logging and broadcast."""
import asyncio
from unittest.mock import MagicMock, call, patch

from app.core.events import bcast, bcast_batch, log_event


class TestLogEvent:
    @patch("app.core.events._audit_persist")
    @patch("app.core.events.compute_integrity", return_value=None)
    @patch("app.core.events.new_id", return_value="evt_test")
    @patch("app.core.events.ts_now", return_value="2026-01-01T00:00:00Z")
    def test_basic(self, mock_ts, mock_id, mock_integrity, mock_audit):
        db = MagicMock()
        log_event(db, "p1", "user1", "host", "create", "created host")
        db.add.assert_called_once()
        mock_audit.assert_called_once()

    @patch("app.core.events._audit_persist", side_effect=Exception("fail"))
    @patch("app.core.events.compute_integrity", return_value=None)
    @patch("app.core.events.new_id", return_value="evt_test")
    @patch("app.core.events.ts_now", return_value="2026-01-01T00:00:00Z")
    def test_audit_failure_does_not_raise(self, mock_ts, mock_id, mock_integrity, mock_audit):
        db = MagicMock()
        log_event(db, "p1", "user1", "host", "create", "created host")
        db.add.assert_called_once()

    @patch("app.core.events._audit_persist")
    @patch("app.core.events.compute_integrity", return_value="sha256=abc123")
    @patch("app.core.events.new_id", return_value="evt_test")
    @patch("app.core.events.ts_now", return_value="2026-01-01T00:00:00Z")
    def test_integrity_added(self, mock_ts, mock_id, mock_integrity, mock_audit):
        db = MagicMock()
        log_event(db, "p1", "user1", "host", "create", "label")
        event_dict = mock_audit.call_args[0][0]
        assert event_dict["integrity"] == "sha256=abc123"

    @patch("app.core.events._audit_persist")
    @patch("app.core.events.compute_integrity", return_value=None)
    @patch("app.core.events.new_id", return_value="evt_test")
    @patch("app.core.events.ts_now", return_value="2026-01-01T00:00:00Z")
    def test_none_username(self, mock_ts, mock_id, mock_integrity, mock_audit):
        db = MagicMock()
        log_event(db, "p1", None, "host", "delete", "deleted")
        db.add.assert_called_once()

    @patch("app.core.events._audit_persist")
    @patch("app.core.events.compute_integrity", return_value=None)
    @patch("app.core.events.new_id", return_value="evt_test")
    @patch("app.core.events.ts_now", return_value="2026-01-01T00:00:00Z")
    def test_meta_dict(self, mock_ts, mock_id, mock_integrity, mock_audit):
        db = MagicMock()
        log_event(db, "p1", "u1", "host", "update", "label", meta={"ip": "10.0.0.1"})
        event_dict = mock_audit.call_args[0][0]
        assert event_dict["meta"] == {"ip": "10.0.0.1"}


class TestBcast:
    @patch("app.core.events.manager")
    @patch("app.core.events.asyncio")
    def test_no_running_loop(self, mock_asyncio, mock_manager):
        mock_asyncio.get_running_loop.side_effect = RuntimeError("no loop")
        bcast("p1", "host", "create", {"id": "h1"})

    @patch("app.core.events.manager")
    @patch("app.core.events.asyncio")
    def test_with_running_loop(self, mock_asyncio, mock_manager):
        mock_loop = MagicMock()
        mock_asyncio.get_running_loop.return_value = mock_loop
        bcast("p1", "host", "create", {"id": "h1"})
        mock_loop.call_soon_threadsafe.assert_called_once()

    @patch("app.core.events.manager")
    @patch("app.core.events.asyncio")
    def test_ws_exclude(self, mock_asyncio, mock_manager):
        mock_loop = MagicMock()
        mock_asyncio.get_running_loop.return_value = mock_loop
        ws = MagicMock()
        bcast("p1", "host", "create", {"id": "h1"}, ws=ws)
        call_args = mock_loop.call_soon_threadsafe.call_args
        fn = call_args[0][0]
        assert callable(fn)


class TestBcastBatch:
    @patch("app.core.events.manager")
    @patch("app.core.events.asyncio")
    def test_empty(self, mock_asyncio, mock_manager):
        bcast_batch("p1", [])
        mock_asyncio.get_running_loop.assert_not_called()

    @patch("app.core.events.manager")
    @patch("app.core.events.asyncio")
    def test_with_loop(self, mock_asyncio, mock_manager):
        mock_loop = MagicMock()
        mock_asyncio.get_running_loop.return_value = mock_loop
        events = [
            ("host", "create", {"id": "h1"}),
            ("cred", "update", {"id": "c1"}),
        ]
        bcast_batch("p1", events)
        mock_loop.call_soon_threadsafe.assert_called_once()

    @patch("app.core.events.manager")
    @patch("app.core.events.asyncio")
    def test_fallback_without_loop(self, mock_asyncio, mock_manager):
        mock_asyncio.get_running_loop.side_effect = RuntimeError()
        events = [
            ("host", "create", {"id": "h1"}),
            ("cred", "update", {"id": "c1"}),
        ]
        with patch("app.core.events.bcast") as mock_bcast:
            bcast_batch("p1", events)
            assert mock_bcast.call_count == 2
