"""Tests for C2 sync helper functions and endpoints."""
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi.testclient import TestClient

from app.routers.c2._sync import (
    _c2_update_host_status,
    _c2_enrich_host,
    _c2_upsert_harvested_cred,
    _c2_update_last_sync,
    _trigger_topology_rebuild_if_needed,
    _CONNECTORS,
)
from app.routers.c2._integrations import (
    _status_from_c2_host,
    _c2_owns_host_status,
    _C2_SETTING_KEY,
)


class FakeHost:
    def __init__(self, **kw):
        self.status = kw.get("status", "")
        self.hostname = kw.get("hostname", "")
        self.domain = kw.get("domain", "")
        self.os = kw.get("os", "")
        self.notes = kw.get("notes", "")
        self.tags = kw.get("tags", [])
        self.import_source = kw.get("import_source", "")
        for k, v in kw.items():
            setattr(self, k, v)


class TestC2UpdateHostStatus:
    def test_c2_owns_updates_status(self):
        host = FakeHost(status="unknown", tags=["c2", "adaptix"], import_source="adaptix")
        h = {"alive": True, "beacon_id": "abc", "username": "administrator"}
        _c2_update_host_status(host, "adaptix", h)
        assert host.status == "pwned"

    def test_c2_owns_no_derived_keeps_existing(self):
        host = FakeHost(status="up", tags=["c2", "adaptix"], import_source="adaptix")
        h = {"alive": True}
        _c2_update_host_status(host, "adaptix", h)
        assert host.status == "up"

    def test_not_owner_upgrades_status(self):
        host = FakeHost(status="up", tags=[], import_source="")
        h = {"alive": True, "beacon_id": "x", "username": "SYSTEM"}
        _c2_update_host_status(host, "adaptix", h)
        assert host.status == "owned"

    def test_not_owner_no_upgrade(self):
        host = FakeHost(status="pwned", tags=[], import_source="")
        h = {"alive": True, "beacon_id": "x", "username": "admin"}
        _c2_update_host_status(host, "adaptix", h)
        assert host.status == "pwned"


class TestC2EnrichHost:
    def test_fills_empty_fields(self):
        host = FakeHost()
        h = {"alive": True, "beacon_id": "b1", "username": "admin"}
        _c2_enrich_host(host, "web01", "corp.local", "Windows 10", "some note", "adaptix", h)
        assert host.hostname == "web01"
        assert host.domain == "corp.local"
        assert host.os == "Windows 10"
        assert "some note" in host.notes
        assert "adaptix" in host.tags
        assert host.import_source == "adaptix"

    def test_does_not_overwrite_hostname(self):
        host = FakeHost(hostname="existing")
        _c2_enrich_host(host, "newname", "", "", "", "sliver", {})
        assert host.hostname == "existing"

    def test_os_not_overwritten_for_specific(self):
        host = FakeHost(os="Windows Server 2019")
        _c2_enrich_host(host, "", "", "Linux", "", "sliver", {})
        assert host.os == "Windows Server 2019"

    def test_os_overwritten_when_unknown(self):
        host = FakeHost(os="Unknown")
        _c2_enrich_host(host, "", "", "Windows 11", "", "sliver", {})
        assert host.os == "Windows 11"

    def test_notes_appended_not_duplicated(self):
        host = FakeHost(notes="existing note")
        _c2_enrich_host(host, "", "", "", "existing note", "sliver", {})
        assert host.notes == "existing note"

    def test_import_source_set_when_empty(self):
        host = FakeHost()
        _c2_enrich_host(host, "", "", "", "", "mythic", {})
        assert host.import_source == "mythic"

    def test_import_source_not_overwritten(self):
        host = FakeHost(import_source="sliver")
        _c2_enrich_host(host, "", "", "", "", "mythic", {})
        assert host.import_source == "sliver"


class TestC2UpsertHarvestedCred:
    def test_creates_new_cred(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        c = {"username": "admin", "secret": "pass123", "realm": "CORP", "type": "plain"}
        result = _c2_upsert_harvested_cred(db, "pid1", c, "adaptix")
        assert result is True
        db.add.assert_called_once()

    def test_skips_empty_username(self):
        db = MagicMock()
        result = _c2_upsert_harvested_cred(db, "pid1", {"username": ""}, "adaptix")
        assert result is False
        db.add.assert_not_called()

    def test_skips_none_username(self):
        db = MagicMock()
        result = _c2_upsert_harvested_cred(db, "pid1", {}, "adaptix")
        assert result is False

    def test_skips_existing_cred(self):
        db = MagicMock()
        existing = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = existing
        result = _c2_upsert_harvested_cred(db, "pid1", {"username": "admin"}, "adaptix")
        assert result is False
        db.add.assert_not_called()


class TestC2UpdateLastSync:
    def test_updates_matching_iid(self):
        db = MagicMock()
        setting = MagicMock()
        setting.value = [{"id": "c2_1", "last_sync": None}]
        db.query.return_value.filter.return_value.first.return_value = setting
        _c2_update_last_sync(db, "c2_1", "2025-01-01T00:00:00Z")
        assert setting.value[0]["last_sync"] == "2025-01-01T00:00:00Z"
        db.commit.assert_called_once()

    def test_skips_when_iid_is_none(self):
        db = MagicMock()
        _c2_update_last_sync(db, None, "ts")
        db.query.assert_not_called()

    def test_skips_when_no_setting(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        _c2_update_last_sync(db, "c2_1", "ts")
        db.commit.assert_not_called()

    def test_skips_when_value_not_list(self):
        db = MagicMock()
        setting = MagicMock()
        setting.value = "not a list"
        db.query.return_value.filter.return_value.first.return_value = setting
        _c2_update_last_sync(db, "c2_1", "ts")

    def test_no_match_does_nothing(self):
        db = MagicMock()
        setting = MagicMock()
        setting.value = [{"id": "other", "last_sync": None}]
        db.query.return_value.filter.return_value.first.return_value = setting
        _c2_update_last_sync(db, "c2_1", "ts")


class TestTriggerTopologyRebuild:
    def test_skips_when_no_created_hosts(self):
        _trigger_topology_rebuild_if_needed("pid1", MagicMock(), 0)

    def test_skips_when_negative(self):
        _trigger_topology_rebuild_if_needed("pid1", MagicMock(), -1)

    def test_calls_rebuild_when_hosts_created(self):
        db = MagicMock()
        with patch("app.routers.topology._run_auto_build") as m:
            _trigger_topology_rebuild_if_needed("pid1", db, 5)
            m.assert_called_once_with("pid1", db)

    def test_handles_rebuild_exception(self):
        db = MagicMock()
        with patch("app.routers.topology._run_auto_build", side_effect=Exception("boom")):
            _trigger_topology_rebuild_if_needed("pid1", db, 3)


class TestConnectors:
    def test_all_types_registered(self):
        assert "sliver" in _CONNECTORS
        assert "adaptix" in _CONNECTORS
        assert "mythic" in _CONNECTORS

    def test_connectors_are_async(self):
        for fn in _CONNECTORS.values():
            import asyncio
            assert asyncio.iscoroutinefunction(fn)
