import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from fastapi import HTTPException

from app.routers.c2._exec import (
    _cred_matches_host,
    _cred_matches_project_host,
    _build_rootnotes_cred_dict,
    _build_host_action_session,
    _process_integration_for_host,
    perform_c2_command,
    resolve_c2_cred,
    SUPPORTED_EXEC_C2_TYPES,
)


class TestProcessIntegrationForHost:
    @pytest.mark.asyncio
    async def test_unsupported_type(self):
        with patch("app.routers.c2._exec._LIVE_CONNECTORS", {}):
            await _process_integration_for_host(
                {"type": "unknown"}, set(), [], [], {}, "h1"
            )

    @pytest.mark.asyncio
    async def test_no_live_fn(self):
        with patch("app.routers.c2._exec.SUPPORTED_EXEC_C2_TYPES", {"sliver"}):
            with patch("app.routers.c2._exec._LIVE_CONNECTORS", {"sliver": None}):
                await _process_integration_for_host(
                    {"type": "sliver"}, set(), [], [], {}, "h1"
                )

    @pytest.mark.asyncio
    async def test_sliver_live(self):
        agent = {"ip": "10.0.0.1", "agent_id": "a1", "beacon_id": "", "hostname": "srv",
                 "username": "admin", "domain": "", "os": "Linux", "arch": "x64",
                 "process": "p", "listener": "l", "session_type": "session",
                 "alive": True, "mark": "alive", "last_seen": "now"}
        sessions = []
        c2_creds = []
        bof_catalog = {}
        mock_live = AsyncMock(return_value=[agent])
        with patch("app.routers.c2._exec.SUPPORTED_EXEC_C2_TYPES", {"sliver"}):
            with patch("app.routers.c2._exec._LIVE_CONNECTORS", {"sliver": mock_live}):
                await _process_integration_for_host(
                    {"type": "sliver", "id": "c1"}, {"10.0.0.1"},
                    sessions, c2_creds, bof_catalog, "h1"
                )
                assert len(sessions) == 1

    @pytest.mark.asyncio
    async def test_adaptix_with_creds_and_bof(self):
        sessions = []
        c2_creds = []
        bof_catalog = {}
        mock_live = AsyncMock(return_value=[{"ip": "10.0.0.1"}])
        mock_creds = AsyncMock(return_value=[{"c_creds_id": "cr1"}])
        mock_bof = AsyncMock(return_value=[{"name": "bof1"}])
        with patch("app.routers.c2._exec.SUPPORTED_EXEC_C2_TYPES", {"adaptix"}):
            with patch("app.routers.c2._exec._LIVE_CONNECTORS", {"adaptix": mock_live}):
                with patch("app.routers.c2._exec._adaptix_fetch_creds", mock_creds):
                    with patch("app.routers.c2._exec._adaptix_fetch_bof_catalog", mock_bof):
                        await _process_integration_for_host(
                            {"type": "adaptix", "id": "c1"}, {"10.0.0.1"},
                            sessions, c2_creds, bof_catalog, "h1"
                        )
                        assert len(c2_creds) == 1
                        assert "c1" in bof_catalog

    @pytest.mark.asyncio
    async def test_exception_logged(self):
        mock_live = AsyncMock(side_effect=Exception("conn refused"))
        with patch("app.routers.c2._exec.SUPPORTED_EXEC_C2_TYPES", {"sliver"}):
            with patch("app.routers.c2._exec._LIVE_CONNECTORS", {"sliver": mock_live}):
                await _process_integration_for_host(
                    {"type": "sliver", "id": "c1"}, {"10.0.0.1"},
                    [], [], {}, "h1"
                )

    @pytest.mark.asyncio
    async def test_adaptix_creds_fail(self):
        mock_live = AsyncMock(return_value=[])
        sessions = []
        c2_creds = []
        bof_catalog = {}
        with patch("app.routers.c2._exec.SUPPORTED_EXEC_C2_TYPES", {"adaptix"}):
            with patch("app.routers.c2._exec._LIVE_CONNECTORS", {"adaptix": mock_live}):
                with patch("app.routers.c2._exec._adaptix_fetch_creds",
                           side_effect=Exception("fail")):
                    with patch("app.routers.c2._exec._adaptix_fetch_bof_catalog",
                               return_value=[]):
                        await _process_integration_for_host(
                            {"type": "adaptix", "id": "c1"}, set(),
                            sessions, c2_creds, bof_catalog, "h1"
                        )


class TestPerformC2Command:
    @pytest.mark.asyncio
    async def test_unsupported_type(self):
        with pytest.raises(ValueError, match="not supported"):
            await perform_c2_command(
                MagicMock(), "p1", MagicMock(), {"type": "bad"},
                "a1", "cmd", "command", None, True, 12, "test"
            )

    @pytest.mark.asyncio
    async def test_mythic_exec(self):
        db = MagicMock()
        host = MagicMock()
        host.id = "h1"
        host.ip = "10.0.0.1"
        host.hostname = "srv"
        with patch("app.routers.c2._exec._mythic_execute", new_callable=AsyncMock,
                    return_value={"output": "root"}):
            with patch("app.routers.c2._exec.new_id", return_value="ha1"):
                with patch("app.routers.c2._exec.ts_now", return_value="ts"):
                    with patch("app.core.secret_scrub.scrub_for_cred", side_effect=lambda x, y: x):
                        with patch("app.routers.c2._exec.bcast"):
                            with patch("app.routers.c2._exec.log_event"):
                                result, activity, rendered = await perform_c2_command(
                                    db, "p1", host, {"type": "mythic", "id": "c1"},
                                    "a1", "whoami", "command", None, True, 12, "test exec"
                                )
                                assert result["output"] == "root"
                                assert db.add.called

    @pytest.mark.asyncio
    async def test_sliver_exec(self):
        db = MagicMock()
        host = MagicMock()
        host.id = "h1"
        host.ip = "10.0.0.1"
        host.hostname = "srv"
        with patch("app.routers.c2._exec._sliver_execute", new_callable=AsyncMock,
                    return_value={"output": "admin", "kind": "session"}):
            with patch("app.routers.c2._exec.new_id", return_value="ha1"):
                with patch("app.routers.c2._exec.ts_now", return_value="ts"):
                    with patch("app.core.secret_scrub.scrub_for_cred", side_effect=lambda x, y: x):
                        with patch("app.routers.c2._exec.bcast"):
                            with patch("app.routers.c2._exec.log_event"):
                                result, activity, rendered = await perform_c2_command(
                                    db, "p1", host, {"type": "sliver", "id": "c1"},
                                    "a1", "id", "command", None, True, 12, "test"
                                )
                                assert result["output"] == "admin"

    @pytest.mark.asyncio
    async def test_adaptix_exec(self):
        db = MagicMock()
        host = MagicMock()
        host.id = "h1"
        host.ip = "10.0.0.1"
        host.hostname = "srv"
        with patch("app.routers.c2._exec._adaptix_execute", new_callable=AsyncMock,
                    return_value={"output": "result", "message": ""}):
            with patch("app.routers.c2._exec.new_id", return_value="ha1"):
                with patch("app.routers.c2._exec.ts_now", return_value="ts"):
                    with patch("app.core.secret_scrub.scrub_for_cred", side_effect=lambda x, y: x):
                        with patch("app.routers.c2._exec.bcast"):
                            with patch("app.routers.c2._exec.log_event"):
                                result, activity, rendered = await perform_c2_command(
                                    db, "p1", host, {"type": "adaptix", "id": "c1"},
                                    "a1", "cmd", "command", None, True, 12, "test"
                                )
                                assert result["output"] == "result"

    @pytest.mark.asyncio
    async def test_with_cred_logs_audit(self):
        db = MagicMock()
        host = MagicMock()
        host.id = "h1"
        host.ip = "10.0.0.1"
        host.hostname = "srv"
        cred = {"id": "cr1", "username": "admin", "secret": "pass"}
        with patch("app.routers.c2._exec._mythic_execute", new_callable=AsyncMock,
                    return_value={"output": ""}):
            with patch("app.routers.c2._exec.new_id", return_value="ha1"):
                with patch("app.routers.c2._exec.ts_now", return_value="ts"):
                    with patch("app.core.secret_scrub.scrub_for_cred", side_effect=lambda x, y: x):
                        with patch("app.routers.c2._exec.bcast"):
                            with patch("app.routers.c2._exec.log_event"):
                                result, activity, rendered = await perform_c2_command(
                                    db, "p1", host, {"type": "mythic", "id": "c1"},
                                    "a1", "cmd", "command", cred, True, 12, "test",
                                    actor_username="user1"
                                )


class TestResolveC2Cred:
    @pytest.mark.asyncio
    async def test_no_credential_id(self):
        r = await resolve_c2_cred(MagicMock(), "p1", "", "rootnotes", {})
        assert r is None

    @pytest.mark.asyncio
    async def test_adaptix_c2_source(self):
        with patch("app.routers.c2._exec._adaptix_fetch_creds", new_callable=AsyncMock,
                    return_value=[{"c_creds_id": "c1", "id": "c1"}]):
            r = await resolve_c2_cred(MagicMock(), "p1", "c1", "c2", {"type": "adaptix", "id": "i1"})
            assert r is not None
            assert r["integration_id"] == "i1"

    @pytest.mark.asyncio
    async def test_rootnotes_cred(self):
        db = MagicMock()
        cred = MagicMock()
        cred.id = "cr1"
        cred.username = "admin"
        cred.secret = "enc:pass"
        cred.domain = "corp"
        cred.host = "10.0.0.1"
        cred.type = "plain"
        db.query.return_value.filter.return_value.first.return_value = cred
        with patch("app.routers.c2._exec.decrypt_str", return_value="pass"):
            r = await resolve_c2_cred(db, "p1", "cr1", "rootnotes", {"type": "sliver"})
            assert r["id"] == "cr1"

    @pytest.mark.asyncio
    async def test_rootnotes_not_found(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        r = await resolve_c2_cred(db, "p1", "cr1", "rootnotes", {"type": "sliver"})
        assert r is None
