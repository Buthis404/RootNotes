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


class TestC2UpdateHostStatus:
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


class TestC2EnrichHost:
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


class TestC2UpsertSessionCred:
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


class TestC2UpsertHarvestedCred:
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


class TestC2SyncOneHost:
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


class TestC2UpdateLastSync:
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


class TestTriggerTopologyRebuild:
    def test_no_created(self):
        _trigger_topology_rebuild_if_needed("p1", MagicMock(), 0)

    def test_with_created(self):
        with patch("app.routers.c2._sync.logger"):
            _trigger_topology_rebuild_if_needed("p1", MagicMock(), 1)
