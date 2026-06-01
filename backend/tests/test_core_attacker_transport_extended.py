"""Tests for app.core.attacker_transport — resolution, config building."""
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from app.core.attacker_transport import (
    AttackerHost,
    ResolvedConnection,
    _cred_matches_host,
    _find_exec_target_by_id,
    _find_global_target_by_id,
    _resolve_exec_auto_ssh,
    _resolve_exec_global_ssh,
    _resolve_exec_project_ssh,
    _try_project_ssh,
    build_ssh_config_from_cred,
    list_global_targets_for_project,
    resolve_exec_connection,
    resolve_exec_ssh_configs,
    resolve_project_attacker_host,
    resolve_project_ssh_cred,
    resolve_scan_target,
    require_attacker_ssh,
)


class TestRequireAttackerSsh:
    def test_raises_when_disabled(self):
        with patch("app.core.attacker_transport.registry") as mock_reg:
            mock_reg.get.return_value = None
            with pytest.raises(HTTPException) as exc_info:
                require_attacker_ssh()
            assert exc_info.value.status_code == 404

    def test_passes_when_enabled(self):
        with patch("app.core.attacker_transport.registry") as mock_reg:
            mock_mod = MagicMock()
            mock_mod.enabled = True
            mock_reg.get.return_value = mock_mod
            require_attacker_ssh()


class TestResolveProjectAttackerHost:
    def test_with_explicit_host_id(self):
        db = MagicMock()
        host = MagicMock()
        host.is_attacker = True
        host.role = "attacker"
        db.query.return_value.filter.return_value.filter.return_value.first.return_value = host
        result = resolve_project_attacker_host(db, "p1", host_id="h1")
        assert result == host

    def test_host_not_found(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.filter.return_value.first.return_value = None
        with pytest.raises(HTTPException) as exc_info:
            resolve_project_attacker_host(db, "p1", host_id="h_missing")
        assert exc_info.value.status_code == 404

    def test_auto_find_attacker(self):
        db = MagicMock()
        host = MagicMock()
        host.is_attacker = True
        host.role = "attacker"
        db.query.return_value.filter.return_value.filter.return_value.order_by.return_value.first.return_value = host
        result = resolve_project_attacker_host(db, "p1")
        assert result.is_attacker is True

    def test_no_attacker_raises(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.filter.return_value.order_by.return_value.first.return_value = None
        with pytest.raises(HTTPException) as exc_info:
            resolve_project_attacker_host(db, "p1")
        assert exc_info.value.status_code == 400

    def test_non_attacker_host_raises(self):
        db = MagicMock()
        host = MagicMock()
        host.is_attacker = False
        host.role = "server"
        db.query.return_value.filter.return_value.filter.return_value.first.return_value = host
        with pytest.raises(HTTPException) as exc_info:
            resolve_project_attacker_host(db, "p1", host_id="h1")
        assert exc_info.value.status_code == 400


class TestResolveProjectSshCred:
    @patch("app.core.attacker_transport.decrypt_str", return_value="secret")
    def test_explicit_cred_found(self, mock_dec):
        db = MagicMock()
        cred = MagicMock()
        cred.host_ids = ["h1"]
        db.query.return_value.filter.return_value.filter.return_value.first.return_value = cred
        host = MagicMock(id="h1")
        result = resolve_project_ssh_cred(db, "p1", host, cred_id="c1")
        assert result == cred

    def test_explicit_cred_not_found(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.filter.return_value.first.return_value = None
        host = MagicMock(id="h1")
        with pytest.raises(HTTPException) as exc_info:
            resolve_project_ssh_cred(db, "p1", host, cred_id="c_missing")
        assert exc_info.value.status_code == 404

    @patch("app.core.attacker_transport.decrypt_str", return_value="secret")
    def test_auto_find_cred(self, mock_dec):
        db = MagicMock()
        cred = MagicMock()
        cred.host_ids = ["h1"]
        cred.secret = "enc"
        cred.type = "plain"
        cred.service = "ssh"
        cred.username = "root"
        db.query.return_value.filter.return_value.all.return_value = [cred]
        host = MagicMock(id="h1", ip="10.0.0.1", hostname="srv1")
        result = resolve_project_ssh_cred(db, "p1", host)
        assert result == cred

    @patch("app.core.attacker_transport.decrypt_str", return_value="secret")
    def test_no_matching_cred(self, mock_dec):
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = []
        host = MagicMock(id="h1", ip="10.0.0.1", hostname="srv1")
        result = resolve_project_ssh_cred(db, "p1", host)
        assert result is None


class TestListGlobalTargetsForProject:
    def test_filters_by_project(self):
        targets = [
            {"id": "t1", "enabled": True, "project_ids": ["p1"]},
            {"id": "t2", "enabled": True, "project_ids": ["p2"]},
            {"id": "t3", "enabled": True, "project_ids": []},
        ]
        with patch("app.core.attacker_transport.list_attacker_targets", return_value=targets):
            result = list_global_targets_for_project("p1")
            ids = [t["id"] for t in result]
            assert "t1" in ids
            assert "t3" in ids
            assert "t2" not in ids

    def test_excludes_disabled(self):
        targets = [
            {"id": "t1", "enabled": False, "project_ids": []},
        ]
        with patch("app.core.attacker_transport.list_attacker_targets", return_value=targets):
            result = list_global_targets_for_project("p1")
            assert len(result) == 0


class TestResolveScanTarget:
    def test_no_targets_raises(self):
        with patch("app.core.attacker_transport.list_attacker_targets_for_exec", return_value=[]):
            with pytest.raises(HTTPException) as exc_info:
                resolve_scan_target("p1")
            assert exc_info.value.status_code == 400

    def test_explicit_target_id(self):
        targets = [{"id": "t1", "enabled": True, "is_operator": True}]
        with patch("app.core.attacker_transport.list_attacker_targets_for_exec", return_value=targets), \
             patch("app.core.attacker_transport.list_attacker_targets", return_value=targets):
            result = resolve_scan_target("p1", target_id="t1")
            assert result["id"] == "t1"

    def test_target_not_found(self):
        with patch("app.core.attacker_transport.list_attacker_targets_for_exec", return_value=[{"id": "t1", "enabled": True}]), \
             patch("app.core.attacker_transport.list_attacker_targets", return_value=[{"id": "t1"}]):
            with pytest.raises(HTTPException) as exc_info:
                resolve_scan_target("p1", target_id="t_missing")
            assert exc_info.value.status_code == 404

    def test_pivot_only_target(self):
        targets_exec = [{"id": "t1", "enabled": True, "is_operator": True}]
        targets_all = [{"id": "t1", "enabled": True, "is_operator": False}]
        with patch("app.core.attacker_transport.list_attacker_targets_for_exec", return_value=targets_exec), \
             patch("app.core.attacker_transport.list_attacker_targets", return_value=targets_all):
            with pytest.raises(HTTPException) as exc_info:
                resolve_scan_target("p1", target_id="t1")
            assert "pivots only" in str(exc_info.value.detail)

    def test_auto_selects_first_project_target(self):
        targets = [
            {"id": "t1", "enabled": True, "is_operator": True, "project_ids": []},
        ]
        with patch("app.core.attacker_transport.list_attacker_targets_for_exec", return_value=targets):
            result = resolve_scan_target("p1")
            assert result["id"] == "t1"


class TestTryProjectSsh:
    @patch("app.core.attacker_transport.build_ssh_config_from_cred", return_value={"host": "10.0.0.1"})
    @patch("app.core.attacker_transport.resolve_project_ssh_cred")
    @patch("app.core.attacker_transport.resolve_project_attacker_host")
    def test_with_cred(self, mock_host, mock_cred, mock_build):
        host = MagicMock()
        cred = MagicMock()
        mock_host.return_value = host
        mock_cred.return_value = cred
        result = _try_project_ssh(MagicMock(), "p1", "auto", None, None)
        assert result is not None

    @patch("app.core.attacker_transport.resolve_project_ssh_cred", return_value=None)
    @patch("app.core.attacker_transport.resolve_project_attacker_host")
    def test_no_cred_project_mode(self, mock_host, mock_cred):
        mock_host.return_value = MagicMock()
        with pytest.raises(HTTPException):
            _try_project_ssh(MagicMock(), "p1", "project", None, None)

    @patch("app.core.attacker_transport.resolve_project_ssh_cred", return_value=None)
    @patch("app.core.attacker_transport.resolve_project_attacker_host")
    def test_no_cred_auto_mode(self, mock_host, mock_cred):
        mock_host.return_value = MagicMock()
        result = _try_project_ssh(MagicMock(), "p1", "auto", None, None)
        assert result is None


class TestResolveExecConnection:
    @patch("app.core.attacker_transport._try_project_ssh", return_value=None)
    @patch("app.core.attacker_transport.list_global_targets_for_project", return_value=[])
    def test_no_targets_raises(self, mock_list, mock_try):
        with pytest.raises(HTTPException) as exc_info:
            resolve_exec_connection(MagicMock(), "p1")
        assert exc_info.value.status_code == 400


class TestResolveExecSshConfigs:
    @patch("app.core.attacker_transport._resolve_exec_project_ssh", return_value=[{"host": "10.0.0.1"}])
    def test_with_host_id(self, mock_resolve):
        result = resolve_exec_ssh_configs(MagicMock(), "p1", attacker_host_id="h1")
        assert len(result) == 1

    @patch("app.core.attacker_transport._resolve_exec_global_ssh", return_value=[{"host": "10.0.0.2"}])
    def test_with_target_id(self, mock_resolve):
        result = resolve_exec_ssh_configs(MagicMock(), "p1", attacker_target_id="t1")
        assert len(result) == 1

    @patch("app.core.attacker_transport._resolve_exec_auto_ssh", return_value=[{"host": "10.0.0.3"}])
    def test_auto_mode(self, mock_resolve):
        result = resolve_exec_ssh_configs(MagicMock(), "p1")
        assert len(result) == 1
