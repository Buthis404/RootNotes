"""Extended tests for app.routers.c2._sync — helper functions."""
import pytest
from unittest.mock import MagicMock, patch

from app.routers.c2._sync import (
    _c2_update_host_status,
    _c2_enrich_host,
    _c2_upsert_session_cred,
    _c2_upsert_harvested_cred,
    _c2_record_c2_activities,
    _c2_update_last_sync,
    _do_project_sync_inner,
)


class TestC2UpsertSessionCred:
    def test_empty_username_returns_zero(self):
        db = MagicMock()
        assert _c2_upsert_session_cred(db, "p1", "10.0.0.1", "", "sliver") == 0

    def test_backslash_split(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        with patch("app.core.db_upsert.try_insert_or_get", return_value=(MagicMock(), True)):
            result = _c2_upsert_session_cred(db, "p1", "10.0.0.1", "DOMAIN\\user1", "sliver")
            assert result == 1

    def test_at_split(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        with patch("app.core.db_upsert.try_insert_or_get", return_value=(MagicMock(), True)):
            result = _c2_upsert_session_cred(db, "p1", "10.0.0.1", "user2@domain.local", "sliver")
            assert result == 1

    def test_existing_cred_returns_zero(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = MagicMock()
        assert _c2_upsert_session_cred(db, "p1", "10.0.0.1", "admin", "sliver") == 0


class TestC2UpsertHarvestedCred:
    def test_empty_username(self):
        db = MagicMock()
        assert _c2_upsert_harvested_cred(db, "p1", {"username": ""}, "sliver") is False

    def test_existing_cred(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = MagicMock()
        assert _c2_upsert_harvested_cred(db, "p1", {"username": "admin", "realm": ""}, "sliver") is False

    def test_new_cred(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        result = _c2_upsert_harvested_cred(
            db, "p1", {"username": "newuser", "secret": "hash", "type": "ntlm", "realm": "DOM"}, "sliver"
        )
        assert result is True
        db.add.assert_called_once()


class TestC2UpdateLastSync:
    def test_no_iid(self):
        db = MagicMock()
        _c2_update_last_sync(db, None, "2025-01-01")
        db.query.assert_not_called()

    def test_no_setting_row(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        _c2_update_last_sync(db, "iid-1", "2025-01-01")
        db.commit.assert_not_called()

    def test_updates_timestamp(self):
        setting = MagicMock()
        setting.value = [{"id": "iid-1"}, {"id": "iid-2"}]
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = setting
        _c2_update_last_sync(db, "iid-1", "2025-01-01")
        assert setting.value[0]["last_sync"] == "2025-01-01"
        db.commit.assert_called()


class TestC2RecordC2Activities:
    def test_records_session(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        host_obj = MagicMock()
        host_obj.id = "h1"
        _c2_record_c2_activities(
            db, "p1", {"name": "test"}, "sliver", "2025-01-01",
            [(host_obj, {})], [host_obj],
        )
        db.add.assert_called()

    def test_updates_existing(self):
        existing = MagicMock()
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = existing
        host_obj = MagicMock()
        host_obj.id = "h1"
        _c2_record_c2_activities(
            db, "p1", {"name": "test"}, "sliver", "2025-01-01",
            [(host_obj, {})], [host_obj],
        )
        assert existing.ts == "2025-01-01"

    def test_cleans_stale(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        host_active = MagicMock()
        host_active.id = "h1"
        host_stale = MagicMock()
        host_stale.id = "h2"
        _c2_record_c2_activities(
            db, "p1", {"name": "test"}, "sliver", "2025-01-01",
            [(host_active, {})], [host_active, host_stale],
        )


class TestC2EnrichHost:
    def test_sets_hostname_if_empty(self):
        host = MagicMock()
        host.hostname = ""
        host.domain = ""
        host.os = "Linux"
        host.notes = ""
        host.tags = []
        host.import_source = ""
        host.status = "up"
        _c2_enrich_host(host, "web01", "dom.local", "Windows", "note", "sliver", {"alive": True})
        assert host.hostname == "web01"

    def test_skips_existing_hostname(self):
        host = MagicMock()
        host.hostname = "existing"
        host.domain = ""
        host.os = ""
        host.notes = ""
        host.tags = []
        host.import_source = ""
        host.status = "up"
        _c2_enrich_host(host, "new", "dom", "Unknown", "", "sliver", {})
        assert host.hostname == "existing"
