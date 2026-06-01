"""Consolidated tests for test_core_attacker_transport (merged variant files)."""

# ════════ from test_core_attacker_transport.py ════════
from unittest.mock import MagicMock, patch

from fastapi import HTTPException

from app.core.attacker_transport import (
    AttackerHost,
    ResolvedConnection,
    _cred_matches_host,
    _find_exec_target_by_id,
    _find_global_target_by_id,
    build_ssh_config_from_cred,
    list_global_targets_for_project,
    require_attacker_ssh,
)


class TestCredMatchesHost:
    def test_match_by_host_ids(self):
        cred = MagicMock(host_ids=["h1", "h2"])
        host = MagicMock(id="h1", ip="10.0.0.1", hostname="srv1")
        assert _cred_matches_host(cred, host) is True

    def test_match_by_ip(self):
        cred = MagicMock(host_ids=[], host="10.0.0.1")
        host = MagicMock(id="h1", ip="10.0.0.1", hostname="srv1")
        assert _cred_matches_host(cred, host) is True

    def test_match_by_hostname(self):
        cred = MagicMock(host_ids=[], host="srv1")
        host = MagicMock(id="h1", ip="10.0.0.1", hostname="srv1")
        assert _cred_matches_host(cred, host) is True

    def test_no_match(self):
        cred = MagicMock(host_ids=[], host="10.0.0.2")
        host = MagicMock(id="h1", ip="10.0.0.1", hostname="srv1")
        assert _cred_matches_host(cred, host) is False

    def test_empty_host_ids(self):
        cred = MagicMock(host_ids=None, host="")
        host = MagicMock(id="h1", ip="10.0.0.1", hostname="srv1")
        assert _cred_matches_host(cred, host) is False


class TestBuildSshConfigFromCred:
    @patch("app.core.attacker_transport.decrypt_str", return_value="decrypted_secret")
    def test_plain_cred(self, mock_decrypt):
        host = MagicMock(ip="10.0.0.1")
        cred = MagicMock(username="root", secret="enc_secret", type="plain")
        cfg = build_ssh_config_from_cred(host, cred)
        assert cfg["host"] == "10.0.0.1"
        assert cfg["username"] == "root"
        assert cfg["password"] == "decrypted_secret"
        assert cfg["private_key"] == ""
        assert cfg["port"] == 22

    @patch("app.core.attacker_transport.decrypt_str", return_value="key_content")
    def test_key_cred(self, mock_decrypt):
        host = MagicMock(ip="10.0.0.1")
        cred = MagicMock(username="root", secret="enc_key", type="key")
        cfg = build_ssh_config_from_cred(host, cred)
        assert cfg["private_key"] == "key_content"
        assert cfg["password"] == ""

    @patch("app.core.attacker_transport.decrypt_str", return_value="secret")
    def test_fallback_overrides(self, mock_decrypt):
        host = MagicMock(ip="10.0.0.1")
        cred = MagicMock(username="admin", secret="enc", type="plain")
        cfg = build_ssh_config_from_cred(host, cred, {"port": 2222, "known_hosts_policy": "ignore"})
        assert cfg["port"] == 2222
        assert cfg["known_hosts_policy"] == "ignore"

    @patch("app.core.attacker_transport.decrypt_str", return_value="secret")
    def test_no_fallback(self, mock_decrypt):
        host = MagicMock(ip="10.0.0.1")
        cred = MagicMock(username="admin", secret="enc", type="plain")
        cfg = build_ssh_config_from_cred(host, cred)
        assert cfg["known_hosts_policy"] == "accept_new"


class TestRequireAttackerSsh_base:
    @patch("app.core.attacker_transport.registry")
    def test_enabled(self, mock_registry):
        module = MagicMock(enabled=True)
        mock_registry.get.return_value = module
        require_attacker_ssh()

    @patch("app.core.attacker_transport.registry")
    def test_disabled(self, mock_registry):
        mock_registry.get.return_value = None
        try:
            require_attacker_ssh()
            assert False, "Should have raised"
        except HTTPException as e:
            assert e.status_code == 404

    @patch("app.core.attacker_transport.registry")
    def test_module_disabled(self, mock_registry):
        module = MagicMock(enabled=False)
        mock_registry.get.return_value = module
        try:
            require_attacker_ssh()
            assert False, "Should have raised"
        except HTTPException as e:
            assert e.status_code == 404


class TestListGlobalTargetsForProject_base:
    @patch("app.core.attacker_transport.list_attacker_targets")
    def test_empty(self, mock_list):
        mock_list.return_value = []
        assert list_global_targets_for_project("p1") == []

    @patch("app.core.attacker_transport.list_attacker_targets")
    def test_filters_by_project(self, mock_list):
        mock_list.return_value = [
            {"id": "t1", "host": "1.1.1.1", "enabled": True, "project_ids": ["p1"]},
            {"id": "t2", "host": "2.2.2.2", "enabled": True, "project_ids": ["p2"]},
        ]
        result = list_global_targets_for_project("p1")
        assert len(result) == 1
        assert result[0]["id"] == "t1"

    @patch("app.core.attacker_transport.list_attacker_targets")
    def test_visible_to_all_when_no_project_ids(self, mock_list):
        mock_list.return_value = [
            {"id": "t1", "host": "1.1.1.1", "enabled": True, "project_ids": []},
        ]
        result = list_global_targets_for_project("any_project")
        assert len(result) == 1

    @patch("app.core.attacker_transport.list_attacker_targets")
    def test_disabled_filtered(self, mock_list):
        mock_list.return_value = [
            {"id": "t1", "host": "1.1.1.1", "enabled": False},
        ]
        result = list_global_targets_for_project("p1")
        assert len(result) == 0

    @patch("app.core.attacker_transport.list_attacker_targets")
    def test_result_fields(self, mock_list):
        mock_list.return_value = [
            {"id": "t1", "name": "My Target", "host": "1.1.1.1", "port": 2222, "username": "root", "enabled": True, "project_ids": []},
        ]
        result = list_global_targets_for_project("p1")
        assert result[0]["source"] == "global"
        assert result[0]["port"] == 2222


class TestFindGlobalTargetById:
    @patch("app.core.attacker_transport.list_attacker_targets")
    def test_found(self, mock_list):
        mock_list.return_value = [{"id": "t1", "enabled": True}]
        assert _find_global_target_by_id("t1") is not None

    @patch("app.core.attacker_transport.list_attacker_targets")
    def test_not_found(self, mock_list):
        mock_list.return_value = [{"id": "t1", "enabled": True}]
        assert _find_global_target_by_id("t2") is None

    @patch("app.core.attacker_transport.list_attacker_targets")
    def test_disabled_not_returned(self, mock_list):
        mock_list.return_value = [{"id": "t1", "enabled": False}]
        assert _find_global_target_by_id("t1") is None


class TestFindExecTargetById:
    @patch("app.core.attacker_transport.list_attacker_targets")
    def test_operator_target(self, mock_list):
        mock_list.return_value = [{"id": "t1", "enabled": True, "is_operator": True}]
        assert _find_exec_target_by_id("t1") is not None

    @patch("app.core.attacker_transport.list_attacker_targets")
    def test_pivot_only_target_raises(self, mock_list):
        mock_list.return_value = [{"id": "t1", "enabled": True, "is_operator": False}]
        try:
            _find_exec_target_by_id("t1")
            assert False, "Should have raised"
        except HTTPException as e:
            assert e.status_code == 400

    @patch("app.core.attacker_transport.list_attacker_targets")
    def test_not_found(self, mock_list):
        mock_list.return_value = []
        assert _find_exec_target_by_id("t1") is None


class TestDataClasses:
    def test_attacker_host(self):
        host = MagicMock()
        ah = AttackerHost(host=host)
        assert ah.host is host
        assert ah.cred is None

    def test_resolved_connection(self):
        rc = ResolvedConnection(ssh_config={"host": "10.0.0.1"})
        assert rc.ssh_config["host"] == "10.0.0.1"
        assert rc.candidates == []
        assert rc.global_target is None


# ════════ from test_core_attacker_transport_extended.py ════════
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


class TestRequireAttackerSsh_extended:
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


class TestListGlobalTargetsForProject_extended:
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
