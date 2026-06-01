import pytest
import json
from unittest.mock import MagicMock, patch, AsyncMock
from fastapi import HTTPException
import httpx

from app.routers.c2._mythic import (
    _mythic_auth_headers,
    _mythic_graphql,
    _mythic_parse_ip,
    _mythic_cb_to_host,
    _mythic_cred_result,
    _mythic_resolve_callback_db_id,
    _build_mythic_task_dict,
    _mythic_cb_note,
    _mythic_sync,
    _mythic_ensure_cb_id,
    _mythic_poll_task,
    _mythic_execute,
    _mythic_live_agents,
    _mythic_fetch_agent_tasks,
)


class TestMythicAuthHeaders:
    @pytest.mark.asyncio
    async def test_token(self):
        client = MagicMock()
        r = await _mythic_auth_headers({"token": "mytoken"}, client)
        assert r == {"apitoken": "mytoken"}

    @pytest.mark.asyncio
    async def test_password_login(self):
        client = MagicMock()
        resp = MagicMock()
        resp.json.return_value = {"access_token": "jwt123"}
        resp.raise_for_status = MagicMock()
        client.post = AsyncMock(return_value=resp)
        r = await _mythic_auth_headers({"url": "http://mythic", "username": "u", "password": "p"}, client)
        assert r == {"Authorization": "Bearer jwt123"}

    @pytest.mark.asyncio
    async def test_password_login_token_key(self):
        client = MagicMock()
        resp = MagicMock()
        resp.json.return_value = {"token": "jwt456"}
        resp.raise_for_status = MagicMock()
        client.post = AsyncMock(return_value=resp)
        r = await _mythic_auth_headers({"url": "http://mythic"}, client)
        assert r == {"Authorization": "Bearer jwt456"}

    @pytest.mark.asyncio
    async def test_password_login_no_token(self):
        client = MagicMock()
        resp = MagicMock()
        resp.json.return_value = {}
        resp.raise_for_status = MagicMock()
        client.post = AsyncMock(return_value=resp)
        with pytest.raises(HTTPException) as exc_info:
            await _mythic_auth_headers({"url": "http://mythic"}, client)
        assert exc_info.value.status_code == 400


class TestMythicGraphql:
    @pytest.mark.asyncio
    async def test_success(self):
        client = MagicMock()
        resp = MagicMock()
        resp.json.return_value = {"data": {"callback": []}}
        resp.raise_for_status = MagicMock()
        client.post = AsyncMock(return_value=resp)
        r = await _mythic_graphql({"url": "http://m"}, client, "query {}", {})
        assert r == {"callback": []}

    @pytest.mark.asyncio
    async def test_graphql_error(self):
        client = MagicMock()
        resp = MagicMock()
        resp.json.return_value = {"errors": ["bad"]}
        resp.raise_for_status = MagicMock()
        client.post = AsyncMock(return_value=resp)
        with pytest.raises(HTTPException) as exc_info:
            await _mythic_graphql({"url": "http://m"}, client, "query {}", {})
        assert exc_info.value.status_code == 400


class TestMythicSync:
    @pytest.mark.asyncio
    async def test_basic(self):
        mock_auth = AsyncMock(return_value={"apitoken": "t"})
        mock_gql = AsyncMock(return_value={
            "callback": [{"ip": "10.0.0.1", "host": "srv", "active": True}],
            "credential": [{"account": "admin", "credential_text": "x"}],
        })
        with patch("app.routers.c2._mythic._mythic_auth_headers", mock_auth):
            with patch("app.routers.c2._mythic._mythic_graphql", mock_gql):
                r = await _mythic_sync({"url": "http://m", "verify_ssl": False})
                assert len(r["hosts"]) == 1
                assert len(r["creds"]) == 1


class TestMythicEnsureCbId:
    @pytest.mark.asyncio
    async def test_already_set(self):
        r = await _mythic_ensure_cb_id({}, MagicMock(), {}, 42, "abc")
        assert r == 42

    @pytest.mark.asyncio
    async def test_lookup(self):
        mock_gql = AsyncMock(return_value={"callback": [{"id": 99}]})
        with patch("app.routers.c2._mythic._mythic_graphql", mock_gql):
            r = await _mythic_ensure_cb_id({}, MagicMock(), {}, None, "abc")
            assert r == 99

    @pytest.mark.asyncio
    async def test_lookup_empty(self):
        mock_gql = AsyncMock(return_value={"callback": []})
        with patch("app.routers.c2._mythic._mythic_graphql", mock_gql):
            with pytest.raises(HTTPException) as exc_info:
                await _mythic_ensure_cb_id({}, MagicMock(), {}, None, "abc")
            assert exc_info.value.status_code == 404


class TestMythicPollTask:
    @pytest.mark.asyncio
    async def test_completed_immediately(self):
        mock_gql = AsyncMock(return_value={
            "task": [{"id": 1, "completed": True, "status": "completed", "stdout": "out",
                      "responses": []}]
        })
        with patch("app.routers.c2._mythic._mythic_graphql", mock_gql):
            with patch("app.routers.c2._mythic.utcnow") as mock_now:
                from datetime import datetime, timezone
                t0 = datetime(2024, 1, 1, tzinfo=timezone.utc)
                mock_now.side_effect = [t0, t0]
                r = await _mythic_poll_task({}, MagicMock(), {}, 1, 10)
                assert r["completed"] is True


class TestMythicExecute:
    @pytest.mark.asyncio
    async def test_basic_no_wait(self):
        mock_auth = AsyncMock(return_value={"apitoken": "t"})
        mock_gql = AsyncMock(return_value={
            "createTask": {"id": 10, "display_id": 1, "status": "submitted", "error": None}
        })
        with patch("app.routers.c2._mythic._mythic_auth_headers", mock_auth):
            with patch("app.routers.c2._mythic._mythic_graphql", mock_gql):
                with patch("app.routers.c2._mythic._mythic_resolve_callback_db_id", return_value=5):
                    r = await _mythic_execute({"url": "http://m", "verify_ssl": False},
                                              "5", "whoami", wait_for_output=False)
                    assert r["accepted"] is True
                    assert r["task_id"] == 10

    @pytest.mark.asyncio
    async def test_with_bang_command(self):
        mock_auth = AsyncMock(return_value={"apitoken": "t"})
        mock_gql = AsyncMock(return_value={
            "createTask": {"id": 11, "display_id": 2, "status": "submitted", "error": None}
        })
        with patch("app.routers.c2._mythic._mythic_auth_headers", mock_auth):
            with patch("app.routers.c2._mythic._mythic_graphql", mock_gql):
                with patch("app.routers.c2._mythic._mythic_resolve_callback_db_id", return_value=5):
                    r = await _mythic_execute({"url": "http://m", "verify_ssl": False},
                                              "5", "!shell whoami", wait_for_output=False)
                    assert r["command"] == "shell"

    @pytest.mark.asyncio
    async def test_create_task_error(self):
        mock_auth = AsyncMock(return_value={"apitoken": "t"})
        mock_gql = AsyncMock(return_value={
            "createTask": {"id": 12, "error": "bad command"}
        })
        with patch("app.routers.c2._mythic._mythic_auth_headers", mock_auth):
            with patch("app.routers.c2._mythic._mythic_graphql", mock_gql):
                with patch("app.routers.c2._mythic._mythic_resolve_callback_db_id", return_value=5):
                    with pytest.raises(HTTPException) as exc_info:
                        await _mythic_execute({"url": "http://m", "verify_ssl": False},
                                              "5", "cmd", wait_for_output=False)
                    assert exc_info.value.status_code == 400


class TestMythicLiveAgents:
    @pytest.mark.asyncio
    async def test_basic(self):
        mock_auth = AsyncMock(return_value={"apitoken": "t"})
        mock_gql = AsyncMock(return_value={
            "callback": [
                {"ip": "10.0.0.1", "host": "srv", "active": True, "user": "admin",
                 "domain": "corp", "os": "Win", "architecture": "x64",
                 "process_name": "p", "agent_callback_id": "cb1", "last_checkin": "now"},
            ]
        })
        with patch("app.routers.c2._mythic._mythic_auth_headers", mock_auth):
            with patch("app.routers.c2._mythic._mythic_graphql", mock_gql):
                r = await _mythic_live_agents({"url": "http://m", "verify_ssl": False})
                assert len(r) == 1
                assert r[0]["ip"] == "10.0.0.1"


class TestMythicFetchAgentTasks:
    @pytest.mark.asyncio
    async def test_basic(self):
        mock_auth = AsyncMock(return_value={"apitoken": "t"})
        mock_gql = AsyncMock(return_value={
            "task": [
                {"id": 1, "display_id": 1, "command_name": "shell", "params": "whoami",
                 "status": "completed", "completed": True, "timestamp": "now",
                 "stdout": "root", "responses": [],
                 "operator": {"username": "admin"}},
            ]
        })
        with patch("app.routers.c2._mythic._mythic_auth_headers", mock_auth):
            with patch("app.routers.c2._mythic._mythic_graphql", mock_gql):
                r = await _mythic_fetch_agent_tasks(
                    {"url": "http://m", "verify_ssl": False}, "1", limit=10
                )
                assert len(r) == 1
                assert r[0]["completed"] is True

    @pytest.mark.asyncio
    async def test_string_callback_id_lookup(self):
        mock_auth = AsyncMock(return_value={"apitoken": "t"})
        gql_responses = [
            {"callback": [{"id": 42}]},
            {"task": []},
        ]
        mock_gql = AsyncMock(side_effect=gql_responses)
        with patch("app.routers.c2._mythic._mythic_auth_headers", mock_auth):
            with patch("app.routers.c2._mythic._mythic_graphql", mock_gql):
                r = await _mythic_fetch_agent_tasks(
                    {"url": "http://m", "verify_ssl": False}, "abc123", limit=10
                )
                assert r == []
