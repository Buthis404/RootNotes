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
