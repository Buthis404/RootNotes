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


class TestExtractCommandTargetHint:
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
