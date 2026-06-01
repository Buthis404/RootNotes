"""Extended tests for attacker_exec helper functions."""
import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from fastapi import HTTPException
from fastapi.testclient import TestClient
from datetime import datetime, timezone

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
TS = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    r = module_client.post("/api/projects", json={"name": "AttackerExecExt", "added": TS, "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]
    yield
    module_client.post("/api/auth/logout")


class TestExtractCommandTargetHint:
    def test_returns_command(self):
        from app.routers.attacker_exec import _extract_command_target_hint
        assert _extract_command_target_hint("whoami") == "whoami"

    def test_empty(self):
        from app.routers.attacker_exec import _extract_command_target_hint
        assert _extract_command_target_hint("") == ""


class TestRequireEnabled:
    def test_raises_when_disabled(self):
        from app.routers.attacker_exec import _require_enabled
        with patch("app.routers.attacker_exec.require_attacker_ssh", side_effect=HTTPException(404, "disabled")):
            with pytest.raises(HTTPException) as exc_info:
                _require_enabled()
            assert exc_info.value.status_code == 404


class TestResolveAttackerHost:
    def test_delegates(self):
        from app.routers.attacker_exec import _resolve_attacker_host
        mock_host = MagicMock()
        with patch("app.routers.attacker_exec.resolve_project_attacker_host", return_value=mock_host) as m:
            result = _resolve_attacker_host(MagicMock(), "pid1", "host1")
            m.assert_called_once()
            assert result == mock_host


class TestListExecutionTargets:
    def test_returns_404_when_disabled(self, module_client: TestClient):
        with patch("app.routers.attacker_exec.require_attacker_ssh", side_effect=HTTPException(404)):
            r = module_client.get(f"/api/projects/{_state['pid']}/attacker-exec/targets")
            assert r.status_code == 404


class TestExecuteEndpoint:
    def test_invalid_execution_mode(self, module_client: TestClient):
        with patch("app.routers.attacker_exec.require_attacker_ssh"):
            r = module_client.post(f"/api/projects/{_state['pid']}/attacker-exec", json={
                "command": "whoami",
                "execution_mode": "invalid_mode",
            })
            assert r.status_code == 400


class TestAttackerExecBody:
    def test_defaults(self):
        from app.routers.attacker_exec import AttackerExecBody
        body = AttackerExecBody(command="test")
        assert body.execution_mode == "auto"
        assert body.timeout_seconds == 45
        assert body.activity_type == "postex"
        assert body.host_id is None
        assert body.cred_id is None
        assert body.target_id is None
        assert body.snippet_title == ""
