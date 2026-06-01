"""Consolidated tests for test_c2_sync (merged variant files)."""

# ════════ from test_c2_sync_api.py ════════
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


class TestC2UpdateHostStatus_api:
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


class TestC2EnrichHost_api:
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


class TestC2UpsertHarvestedCred_api:
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


class TestC2UpdateLastSync_api:
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


class TestTriggerTopologyRebuild_api:
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


class TestConnectors_api:
    def test_all_types_registered(self):
        assert "sliver" in _CONNECTORS
        assert "adaptix" in _CONNECTORS
        assert "mythic" in _CONNECTORS

    def test_connectors_are_async(self):
        for fn in _CONNECTORS.values():
            import asyncio
            assert asyncio.iscoroutinefunction(fn)


# ════════ from test_c2_sync_extended.py ════════
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


class TestC2UpsertSessionCred_extended:
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


class TestC2UpsertHarvestedCred_extended:
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


class TestC2UpdateLastSync_extended:
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


class TestC2RecordC2Activities_extended:
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


class TestC2EnrichHost_extended:
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


# ════════ from test_c2_sync_final.py ════════
import pytest
from unittest.mock import MagicMock, patch

from app.routers.c2._sync import (
    _c2_update_host_status,
    _c2_enrich_host,
    _c2_upsert_session_cred,
    _c2_upsert_harvested_cred,
    _c2_sync_one_host,
    _c2_record_c2_activities,
    _c2_update_last_sync,
    _broadcast_synced_hosts,
    _trigger_topology_rebuild_if_needed,
)


class TestC2UpdateHostStatus_final:
    def test_owns_status_updates(self):
        host = MagicMock()
        host.import_source = "sliver"
        host.tags = ["c2", "sliver"]
        host.status = "up"
        _c2_update_host_status(host, "sliver", {"status": "pwned", "alive": True, "beacon_id": "x", "username": "admin"})
        assert host.status == "pwned"

    def test_not_owner_still_updates_if_better(self):
        host = MagicMock()
        host.import_source = "nmap"
        host.tags = ["nmap"]
        host.status = "up"
        _c2_update_host_status(host, "sliver", {"status": "pwned", "alive": True, "beacon_id": "x", "username": "admin"})
        assert host.status == "pwned"


class TestC2EnrichHost_final:
    def test_enriches(self):
        host = MagicMock()
        host.hostname = ""
        host.domain = ""
        host.os = "Linux"
        host.notes = ""
        host.tags = []
        host.import_source = ""
        host.status = "up"
        _c2_enrich_host(host, "SRV1", "corp.local", "Windows Server", "note text", "sliver", {"status": "up", "alive": True})
        assert host.hostname == "SRV1"
        assert host.domain == "corp.local"
        assert host.os == "Windows Server"
        assert "sliver" in host.tags

    def test_no_overwrite_hostname(self):
        host = MagicMock()
        host.hostname = "EXISTING"
        host.domain = ""
        host.os = ""
        host.notes = ""
        host.tags = []
        host.import_source = ""
        _c2_enrich_host(host, "NEW", "", "", "", "sliver", {"status": "up"})
        assert host.hostname == "EXISTING"


class TestC2UpsertSessionCred_final:
    def test_no_username(self):
        with patch("app.routers.c2._sync.models"):
            result = _c2_upsert_session_cred(MagicMock(), "p1", "10.0.0.1", "", "sliver")
            assert result == 0

    def test_existing_cred(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = MagicMock()
        result = _c2_upsert_session_cred(db, "p1", "10.0.0.1", "admin", "sliver")
        assert result == 0

    def test_new_cred_backslash(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        db.add = MagicMock()
        db.flush = MagicMock()
        with patch("app.core.db_upsert.try_insert_or_get", return_value=(MagicMock(), True)):
            result = _c2_upsert_session_cred(db, "p1", "10.0.0.1", "CORP\\admin", "sliver")
            assert result == 1

    def test_new_cred_at(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        db.add = MagicMock()
        db.flush = MagicMock()
        with patch("app.core.db_upsert.try_insert_or_get", return_value=(MagicMock(), True)):
            result = _c2_upsert_session_cred(db, "p1", "10.0.0.1", "admin@corp.local", "sliver")
            assert result == 1


class TestC2UpsertHarvestedCred_final:
    def test_no_username(self):
        assert _c2_upsert_harvested_cred(MagicMock(), "p1", {"username": ""}, "sliver") is False

    def test_existing(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = MagicMock()
        assert _c2_upsert_harvested_cred(db, "p1", {"username": "admin"}, "sliver") is False

    def test_new(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        result = _c2_upsert_harvested_cred(db, "p1", {"username": "admin", "secret": "pass", "type": "plain"}, "sliver")
        assert result is True


class TestC2SyncOneHost_final:
    def test_no_ip_no_hostname(self):
        result = _c2_sync_one_host(MagicMock(), "p1", {"ip": "", "hostname": ""}, "sliver")
        assert result[0] is None

    def test_hostname_as_ip(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = MagicMock()
        host, c, u, cred = _c2_sync_one_host(db, "p1", {"ip": "", "hostname": "SRV1", "alive": True}, "sliver")
        assert host is not None

    def test_dead_host_not_created(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        result = _c2_sync_one_host(db, "p1", {"ip": "10.0.0.1", "alive": False}, "sliver")
        assert result[0] is None


class TestC2UpdateLastSync_final:
    def test_no_iid(self):
        _c2_update_last_sync(MagicMock(), None, "ts")

    def test_no_setting(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        _c2_update_last_sync(db, "iid1", "ts")


class TestBroadcastSyncedHosts:
    def test_basic(self):
        db = MagicMock()
        host = MagicMock()
        with patch("app.routers.c2._sync.bcast"), \
             patch("app.routers.c2._sync.schemas"):
            _broadcast_synced_hosts(db, "p1", [host])

    def test_exception_handled(self):
        db = MagicMock()
        host = MagicMock()
        db.refresh.side_effect = Exception("fail")
        with patch("app.routers.c2._sync.bcast"), \
             patch("app.routers.c2._sync.schemas"):
            _broadcast_synced_hosts(db, "p1", [host])


class TestTriggerTopologyRebuild_final:
    def test_no_created(self):
        _trigger_topology_rebuild_if_needed("p1", MagicMock(), 0)

    def test_with_created(self):
        with patch("app.routers.c2._sync.logger"):
            _trigger_topology_rebuild_if_needed("p1", MagicMock(), 1)


# ════════ from test_c2_sync_final2.py ════════
import pytest
from unittest.mock import MagicMock, patch

from app.routers.c2._sync import (
    _c2_update_host_status,
    _c2_enrich_host,
    _c2_upsert_session_cred,
    _c2_upsert_harvested_cred,
    _c2_sync_one_host,
    _c2_record_c2_activities,
    _c2_update_last_sync,
    _CONNECTORS,
)


class TestConnectors_final2:
    def test_all_types_present(self):
        assert "sliver" in _CONNECTORS
        assert "adaptix" in _CONNECTORS
        assert "mythic" in _CONNECTORS


class TestC2UpdateHostStatus_final2:
    def test_owns_status_updates(self):
        from unittest.mock import MagicMock
        from app.routers.c2._integrations import _status_from_c2_host, _c2_owns_host_status
        host = MagicMock()
        host.status = "up"
        host.import_source = "sliver"
        host.tags = ["c2", "sliver"]
        h = {"alive": True, "beacon_id": "b1", "username": "admin"}
        _c2_update_host_status(host, "sliver", h)
        assert host.status in ("pwned", "owned", "access", "up", "alive")

    def test_not_owner_keeps_if_better(self):
        from unittest.mock import MagicMock
        host = MagicMock()
        host.status = "pwned"
        host.import_source = "mythic"
        host.tags = []
        h = {"alive": True, "beacon_id": "", "username": "user"}
        _c2_update_host_status(host, "sliver", h)
        assert host.status == "pwned"


class TestC2EnrichHost_final2:
    def test_fills_fields(self):
        from unittest.mock import MagicMock
        host = MagicMock()
        host.hostname = ""
        host.domain = ""
        host.os = "Unknown"
        host.status = "up"
        host.notes = ""
        host.tags = []
        host.import_source = ""
        h = {"alive": True, "beacon_id": "b1", "username": "u"}
        _c2_enrich_host(host, "srv01", "corp", "Windows", "note", "sliver", h)
        assert host.hostname == "srv01"
        assert host.domain == "corp"
        assert host.os == "Windows"

    def test_skips_existing(self):
        from unittest.mock import MagicMock
        host = MagicMock()
        host.hostname = "existing"
        host.domain = "existing"
        host.os = "Linux"
        host.status = "up"
        host.notes = ""
        host.tags = []
        host.import_source = "src"
        h = {"alive": True, "beacon_id": "", "username": ""}
        _c2_enrich_host(host, "new", "new", "Windows", "note", "src", h)
        assert host.hostname == "existing"
        assert host.domain == "existing"


class TestC2UpsertSessionCred_final2:
    def test_no_username(self):
        from unittest.mock import MagicMock
        assert _c2_upsert_session_cred(MagicMock(), "p1", "1.1.1.1", "", "sliver") == 0

    def test_backslash_split(self):
        from unittest.mock import MagicMock, patch
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        db.add = MagicMock()
        with patch("app.core.db_upsert.try_insert_or_get") as mock_tig:
            mock_host = MagicMock()
            mock_tig.return_value = (mock_host, True)
            r = _c2_upsert_session_cred(db, "p1", "1.1.1.1", "CORP\\admin", "sliver")
            assert r == 1

    def test_at_split(self):
        from unittest.mock import MagicMock, patch
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        with patch("app.core.db_upsert.try_insert_or_get") as mock_tig:
            mock_host = MagicMock()
            mock_tig.return_value = (mock_host, True)
            r = _c2_upsert_session_cred(db, "p1", "1.1.1.1", "admin@corp.com", "sliver")
            assert r == 1


class TestC2UpsertHarvestedCred_final2:
    def test_no_username(self):
        from unittest.mock import MagicMock
        assert _c2_upsert_harvested_cred(MagicMock(), "p1", {"username": ""}, "sliver") is False

    def test_existing(self):
        from unittest.mock import MagicMock
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = MagicMock()
        assert _c2_upsert_harvested_cred(db, "p1", {"username": "admin"}, "sliver") is False

    def test_new(self):
        from unittest.mock import MagicMock
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        with patch("app.routers.c2._sync.new_id", return_value="crd1"):
            r = _c2_upsert_harvested_cred(db, "p1", {"username": "admin", "secret": "pass"}, "sliver")
            assert r is True


class TestC2SyncOneHost_final2:
    def test_no_ip_no_hostname(self):
        from unittest.mock import MagicMock
        r = _c2_sync_one_host(MagicMock(), "p1", {"ip": "", "hostname": ""}, "sliver")
        assert r[0] is None

    def test_hostname_as_ip(self):
        from unittest.mock import MagicMock, patch
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        with patch("app.core.db_upsert.try_insert_or_get") as mock_tig:
            mock_host = MagicMock()
            mock_host.id = "h1"
            mock_tig.return_value = (mock_host, True)
            with patch("app.routers.c2._sync._c2_upsert_session_cred", return_value=0):
                r = _c2_sync_one_host(db, "p1", {"ip": "", "hostname": "srv01", "alive": True}, "sliver")
                assert r[0] is not None

    def test_dead_new_host_skipped(self):
        from unittest.mock import MagicMock
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        r = _c2_sync_one_host(db, "p1", {"ip": "10.0.0.1", "hostname": "", "alive": False}, "sliver")
        assert r[0] is None

    def test_existing_host_enriched(self):
        from unittest.mock import MagicMock
        db = MagicMock()
        existing = MagicMock()
        existing.hostname = ""
        existing.domain = ""
        existing.os = "Unknown"
        existing.status = "up"
        existing.notes = ""
        existing.tags = []
        existing.import_source = "sliver"
        db.query.return_value.filter.return_value.first.return_value = existing
        with patch("app.routers.c2._sync._c2_upsert_session_cred", return_value=0):
            r = _c2_sync_one_host(db, "p1", {"ip": "10.0.0.1", "hostname": "srv", "os": "Linux",
                                              "alive": True, "beacon_id": "", "username": ""}, "sliver")
            assert r[2] == 1


class TestC2UpdateLastSync_final2:
    def test_no_iid(self):
        from unittest.mock import MagicMock
        _c2_update_last_sync(MagicMock(), None, "ts")

    def test_no_settings(self):
        from unittest.mock import MagicMock
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        _c2_update_last_sync(db, "iid1", "ts")

    def test_updates(self):
        from unittest.mock import MagicMock
        item = MagicMock()
        item.value = [{"id": "iid1", "last_sync": None}]
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = item
        _c2_update_last_sync(db, "iid1", "new_ts")
        assert item.value[0]["last_sync"] == "new_ts"


class TestC2RecordC2Activities_final2:
    def test_records(self):
        from unittest.mock import MagicMock
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        h1 = MagicMock()
        h1.id = "h1"
        _c2_record_c2_activities(db, "p1", {"name": "test"}, "sliver", "ts",
                                  [(h1, {"alive": True})], [h1])
        assert db.add.called

    def test_stale_cleanup(self):
        from unittest.mock import MagicMock
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        h1 = MagicMock()
        h1.id = "h1"
        h2 = MagicMock()
        h2.id = "h2"
        _c2_record_c2_activities(db, "p1", {"name": "test"}, "sliver", "ts",
                                  [(h1, {"alive": True})], [h1, h2])


# ════════ from test_c2_sync_v3.py ════════
import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from fastapi import HTTPException

from app.routers.c2._sync import (
    _c2_upsert_harvested_cred,
    _c2_update_last_sync,
    _c2_record_c2_activities,
    _c2_enrich_host,
    _c2_update_host_status,
    _has_live_session_signal,
    _do_project_sync_inner,
    _do_project_sync,
    _CONNECTORS,
)
from app.routers.c2._integrations import _safe_integration


class TestHasLiveSessionSignal:
    def test_with_beacon_id(self):
        assert _has_live_session_signal({"alive": True, "beacon_id": "b1"}) is True

    def test_alive_no_signal(self):
        assert _has_live_session_signal({"alive": True, "beacon_id": ""}) is False

    def test_dead_with_beacon(self):
        assert _has_live_session_signal({"alive": False, "beacon_id": "b1"}) is True

    def test_with_process(self):
        assert _has_live_session_signal({"process": "implant.exe", "beacon_id": ""}) is True


class TestSafeIntegration:
    def test_masks_secret(self):
        cfg = {"id": "1", "token": "secret123", "password": "pass", "name": "test"}
        r = _safe_integration(cfg)
        assert r["token"] == ""
        assert r["password"] == ""
        assert r["has_token"] is True
        assert r["has_password"] is True

    def test_no_secrets(self):
        cfg = {"id": "1", "name": "test"}
        r = _safe_integration(cfg)
        assert "id" in r
        assert r["has_token"] is False


class TestDoProjectSyncInner:
    @pytest.mark.asyncio
    async def test_basic_sync(self):
        db = MagicMock()
        host_obj = MagicMock()
        host_obj.id = "h1"
        with patch("app.routers.c2._sync._CONNECTORS", {"sliver": AsyncMock(return_value={
            "hosts": [{"ip": "10.0.0.1", "hostname": "srv", "alive": True, "beacon_id": "b1", "username": "admin"}],
            "creds": [],
        })}):
            with patch("app.routers.c2._sync._c2_sync_one_host", return_value=(host_obj, 1, 0, 0)):
                with patch("app.routers.c2._sync._c2_record_c2_activities"):
                    with patch("app.routers.c2._sync._c2_update_last_sync"):
                        with patch("app.routers.c2._sync._broadcast_synced_hosts"):
                            with patch("app.routers.c2._sync._trigger_topology_rebuild_if_needed"):
                                with patch("app.routers.c2._sync.log_event"):
                                    with patch("app.routers.c2._sync.ts_now", return_value="ts"):
                                        r = await _do_project_sync_inner(
                                            {"type": "sliver", "name": "test"}, "p1", db, "iid1"
                                        )
                                        assert r["ok"] is True
                                        assert r["hosts_created"] == 1

    @pytest.mark.asyncio
    async def test_unsupported_type(self):
        db = MagicMock()
        with patch("app.routers.c2._sync._CONNECTORS", {}):
            with pytest.raises(HTTPException) as exc_info:
                await _do_project_sync_inner({"type": "unknown", "name": "x"}, "p1", db)
            assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_c2_error(self):
        db = MagicMock()
        with patch("app.routers.c2._sync._CONNECTORS", {"sliver": AsyncMock(return_value={
            "error": "conn refused", "hosts": [], "creds": [],
        })}):
            with pytest.raises(HTTPException) as exc_info:
                await _do_project_sync_inner({"type": "sliver", "name": "x"}, "p1", db)
            assert "conn refused" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_with_creds(self):
        db = MagicMock()
        host_obj = MagicMock()
        host_obj.id = "h1"
        with patch("app.routers.c2._sync._CONNECTORS", {"sliver": AsyncMock(return_value={
            "hosts": [{"ip": "10.0.0.1", "hostname": "srv", "alive": True, "beacon_id": "", "username": ""}],
            "creds": [{"username": "admin", "secret": "pass"}],
        })}):
            with patch("app.routers.c2._sync._c2_sync_one_host", return_value=(host_obj, 1, 0, 0)):
                with patch("app.routers.c2._sync._c2_upsert_harvested_cred", return_value=True):
                    with patch("app.routers.c2._sync._c2_record_c2_activities"):
                        with patch("app.routers.c2._sync._c2_update_last_sync"):
                            with patch("app.routers.c2._sync._broadcast_synced_hosts"):
                                with patch("app.routers.c2._sync._trigger_topology_rebuild_if_needed"):
                                    with patch("app.routers.c2._sync.log_event"):
                                        with patch("app.routers.c2._sync.ts_now", return_value="ts"):
                                            r = await _do_project_sync_inner(
                                                {"type": "sliver", "name": "test"}, "p1", db
                                            )
                                            assert r["creds_created"] == 1


class TestDoProjectSync:
    @pytest.mark.asyncio
    async def test_success(self):
        db = MagicMock()
        with patch("app.routers.c2._sync._do_project_sync_inner", new_callable=AsyncMock,
                    return_value={"hosts_found": 1, "hosts_created": 1, "hosts_updated": 0, "creds_created": 0}):
            with patch("app.routers.c2._sync.start_job", return_value="job1"):
                with patch("app.routers.c2._sync.finish_job"):
                    r = await _do_project_sync({"type": "sliver", "url": "http://x"}, "p1", db, iid="i1")
                    assert r["hosts_found"] == 1

    @pytest.mark.asyncio
    async def test_failure(self):
        db = MagicMock()
        with patch("app.routers.c2._sync._do_project_sync_inner", new_callable=AsyncMock,
                    side_effect=Exception("boom")):
            with patch("app.routers.c2._sync.start_job", return_value="job1"):
                with patch("app.routers.c2._sync.finish_job") as mock_finish:
                    with pytest.raises(Exception, match="boom"):
                        await _do_project_sync({"type": "sliver"}, "p1", db)
                    mock_finish.assert_called_once()
                    call_kwargs = mock_finish.call_args
                    assert call_kwargs[1]["status"] == "failed"


class TestC2EnrichHostMore:
    def test_updates_notes(self):
        host = MagicMock()
        host.hostname = "srv"
        host.domain = "corp"
        host.os = "Linux"
        host.status = "up"
        host.notes = "old note"
        host.tags = []
        host.import_source = ""
        h = {"alive": True, "beacon_id": "b1", "username": "admin"}
        _c2_enrich_host(host, "srv", "corp", "Linux", "new note", "sliver", h)
        assert "new note" in host.notes

    def test_sets_import_source(self):
        host = MagicMock()
        host.hostname = ""
        host.domain = ""
        host.os = "Unknown"
        host.status = "up"
        host.notes = ""
        host.tags = []
        host.import_source = ""
        h = {"alive": True, "beacon_id": "", "username": ""}
        _c2_enrich_host(host, "", "", "Linux", "", "sliver", h)
        assert host.import_source == "sliver"


class TestC2RecordC2ActivitiesMore:
    def test_existing_activity_update(self):
        db = MagicMock()
        existing_act = MagicMock()
        existing_act.ts = "old"
        db.query.return_value.filter.return_value.first.return_value = existing_act
        h1 = MagicMock()
        h1.id = "h1"
        _c2_record_c2_activities(db, "p1", {"name": "test"}, "sliver", "ts",
                                  [(h1, {"alive": True})], [h1])
        assert existing_act.ts == "ts"

    def test_exception_is_swallowed(self):
        db = MagicMock()
        db.query.side_effect = Exception("db error")
        h1 = MagicMock()
        h1.id = "h1"
        _c2_record_c2_activities(db, "p1", {"name": "test"}, "sliver", "ts",
                                  [(h1, {"alive": True})], [h1])
