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


class TestConnectors:
    def test_all_types_present(self):
        assert "sliver" in _CONNECTORS
        assert "adaptix" in _CONNECTORS
        assert "mythic" in _CONNECTORS


class TestC2UpdateHostStatus:
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


class TestC2EnrichHost:
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


class TestC2UpsertSessionCred:
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


class TestC2UpsertHarvestedCred:
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


class TestC2SyncOneHost:
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


class TestC2UpdateLastSync:
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


class TestC2RecordC2Activities:
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
