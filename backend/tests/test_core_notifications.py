"""Tests for app.core.notifications — dispatch, config, formatting."""
import asyncio
import json
from unittest.mock import MagicMock, patch

from app.core.notifications import (
    _event_enabled,
    _send_slack,
    _send_telegram,
    _send_webhook,
    dispatch,
    dispatch_sync,
    get_config,
    save_config,
)


class TestEventEnabled:
    def test_enabled_by_default(self):
        assert _event_enabled({}, "anything") is True

    def test_explicitly_enabled(self):
        assert _event_enabled({"events": {"scan": True}}, "scan") is True

    def test_explicitly_disabled(self):
        assert _event_enabled({"events": {"scan": False}}, "scan") is False

    def test_other_event_enabled(self):
        assert _event_enabled({"events": {"scan": False}}, "other") is True


class TestSendTelegram:
    @patch("urllib.request.urlopen")
    def test_success(self, mock_urlopen):
        mock_urlopen.return_value = None
        result = asyncio.get_event_loop().run_until_complete(
            _send_telegram("tok", "chat123", "hello")
        )
        assert result is True

    @patch("urllib.request.urlopen", side_effect=Exception("fail"))
    def test_failure(self, mock_urlopen):
        result = asyncio.get_event_loop().run_until_complete(
            _send_telegram("tok", "chat123", "hello")
        )
        assert result is False


class TestSendSlack:
    @patch("urllib.request.urlopen")
    def test_success(self, mock_urlopen):
        mock_urlopen.return_value = None
        result = asyncio.get_event_loop().run_until_complete(
            _send_slack("https://hooks.slack.com/x", "msg")
        )
        assert result is True

    @patch("urllib.request.urlopen", side_effect=Exception("fail"))
    def test_failure(self, mock_urlopen):
        result = asyncio.get_event_loop().run_until_complete(
            _send_slack("https://hooks.slack.com/x", "msg")
        )
        assert result is False


class TestSendWebhook:
    @patch("urllib.request.urlopen")
    def test_success(self, mock_urlopen):
        mock_urlopen.return_value = None
        result = asyncio.get_event_loop().run_until_complete(
            _send_webhook("https://example.com/hook", {"event": "test"})
        )
        assert result is True

    @patch("urllib.request.urlopen", side_effect=Exception("fail"))
    def test_failure(self, mock_urlopen):
        result = asyncio.get_event_loop().run_until_complete(
            _send_webhook("https://example.com/hook", {})
        )
        assert result is False


class TestDispatch:
    @patch("app.core.notifications._send_telegram")
    @patch("app.core.notifications._send_slack")
    @patch("app.core.notifications._send_webhook")
    def test_dispatch_fires_all_channels(self, mock_wh, mock_slack, mock_tg):
        async def fake_telegram(*a, **kw):
            return True

        async def fake_slack(*a, **kw):
            return True

        async def fake_webhook(*a, **kw):
            return True

        mock_tg.side_effect = fake_telegram
        mock_slack.side_effect = fake_slack
        mock_wh.side_effect = fake_webhook
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        asyncio.get_event_loop().run_until_complete(
            dispatch(db, "scan", "Title", "Body", {"extra": 1})
        )

    def test_dispatch_no_config(self):
        db = MagicMock()
        row = MagicMock()
        row.value = {}
        db.query.return_value.filter.return_value.first.return_value = row
        asyncio.get_event_loop().run_until_complete(
            dispatch(db, "scan", "Title", "Body")
        )

    def test_dispatch_event_disabled(self):
        db = MagicMock()
        row = MagicMock()
        row.value = {"events": {"scan": False}}
        db.query.return_value.filter.return_value.first.return_value = row
        asyncio.get_event_loop().run_until_complete(
            dispatch(db, "scan", "Title", "Body")
        )


class TestDispatchSync:
    def test_dispatch_sync_no_loop(self):
        db = MagicMock()
        dispatch_sync(db, "scan", "Title", "Body")


class TestGetConfig:
    def test_returns_empty_when_no_row(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        cfg = get_config(db)
        assert cfg == {}

    def test_returns_stored_value(self):
        db = MagicMock()
        row = MagicMock()
        row.value = {"telegram": {"enabled": True}}
        db.query.return_value.filter.return_value.first.return_value = row
        cfg = get_config(db)
        assert cfg["telegram"]["enabled"] is True


class TestSaveConfig:
    def test_updates_existing(self):
        db = MagicMock()
        row = MagicMock()
        row.value = {}
        db.query.return_value.filter.return_value.first.return_value = row
        save_config(db, {"slack": {"enabled": True}})
        assert row.value == {"slack": {"enabled": True}}
        db.commit.assert_called()

    def test_creates_new(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        save_config(db, {"webhook": {"enabled": True}})
        db.add.assert_called_once()
        db.commit.assert_called()
