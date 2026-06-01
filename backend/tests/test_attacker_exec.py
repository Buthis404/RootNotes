"""Consolidated tests for test_attacker_exec (merged variant files)."""

# ════════ from test_attacker_exec_extended.py ════════
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


class TestExtractCommandTargetHint_extended:
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


# ════════ from test_attacker_exec_final.py ════════
import pytest
from unittest.mock import MagicMock, patch

from app.routers.attacker_exec import (
    _extract_command_target_hint,
    _resolve_attacker_host,
    _cred_matches_host,
    _resolve_project_cred,
    _build_ssh_config_from_project,
    _list_global_targets_for_project,
    _resolve_global_exec_candidates,
    AttackerExecBody,
)


class TestExtractCommandTargetHint_final:
    def test_returns_command(self):
        assert _extract_command_target_hint("whoami") == "whoami"

    def test_returns_empty(self):
        assert _extract_command_target_hint("") == ""


class TestCredMatchesHost:
    def test_ip_match(self):
        cred = MagicMock()
        host = MagicMock()
        cred.secret = "pass"
        cred.type = "plain"
        with patch("app.routers.attacker_exec._cred_matches_host", return_value=True) as m:
            host.ip = "10.0.0.1"
            host.hostname = "target"
            cred.host = "10.0.0.1"
            result = _cred_matches_host(cred, host)
            assert result is True

    def test_no_match(self):
        cred = MagicMock()
        host = MagicMock()
        with patch("app.core.attacker_transport._cred_matches_host", return_value=False):
            result = _cred_matches_host(cred, host)
            assert result is False


class TestResolveGlobalExecCandidatesNoTargets:
    def test_no_targets_raises(self):
        from fastapi import HTTPException
        body = AttackerExecBody(command="test", target_id="t1")
        with pytest.raises(HTTPException) as exc_info:
            _resolve_global_exec_candidates("p1", body, MagicMock(), [])
        assert exc_info.value.status_code == 404


class TestResolveGlobalExecCandidatesNoEnabled:
    def test_no_enabled_raises(self):
        from fastapi import HTTPException
        body = AttackerExecBody(command="test")
        db = MagicMock()
        with patch("app.routers.attacker_exec.choose_route_aware_target", return_value=None), \
             patch("app.plugins.state.list_attacker_targets", return_value=[]):
            with pytest.raises(HTTPException) as exc_info:
                _resolve_global_exec_candidates("p1", body, db, [{"id": "t1"}])
            assert exc_info.value.status_code == 400


class TestAttackerExecBodyDefaults:
    def test_defaults(self):
        body = AttackerExecBody(command="whoami")
        assert body.execution_mode == "auto"
        assert body.timeout_seconds == 45
        assert body.activity_type == "postex"
        assert body.host_id is None
        assert body.cred_id is None
        assert body.target_id is None


# ════════ from test_attacker_exec_final2.py ════════
import pytest
from unittest.mock import MagicMock, patch

from app.routers.attacker_exec import (
    _resolve_attacker_host,
    _cred_matches_host,
    _resolve_project_cred,
    _build_ssh_config_from_project,
    _list_global_targets_for_project,
    _extract_command_target_hint,
)


class TestAttackerExecHelpers:
    def test_resolve_attacker_host(self):
        with patch("app.routers.attacker_exec.resolve_project_attacker_host", return_value=MagicMock()):
            r = _resolve_attacker_host(MagicMock(), "p1", "h1")
            assert r is not None

    def test_cred_matches_host(self):
        cred = MagicMock()
        host = MagicMock()
        with patch("app.core.attacker_transport._cred_matches_host", return_value=True):
            assert _cred_matches_host(cred, host) is True

    def test_resolve_project_cred(self):
        with patch("app.routers.attacker_exec.resolve_project_ssh_cred", return_value=None):
            r = _resolve_project_cred(MagicMock(), "p1", MagicMock(), None)
            assert r is None

    def test_build_ssh_config(self):
        host = MagicMock()
        cred = MagicMock()
        with patch("app.routers.attacker_exec.build_ssh_config_from_cred", return_value={"host": "1.1.1.1"}):
            r = _build_ssh_config_from_project(host, cred, {})
            assert r["host"] == "1.1.1.1"

    def test_list_global_targets(self):
        with patch("app.routers.attacker_exec.list_global_targets_for_project", return_value=[]):
            r = _list_global_targets_for_project("p1")
            assert r == []

    def test_extract_command_target_hint(self):
        assert _extract_command_target_hint("nmap 10.0.0.1") == "nmap 10.0.0.1"
        assert _extract_command_target_hint("") == ""
