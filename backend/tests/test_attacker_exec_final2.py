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
