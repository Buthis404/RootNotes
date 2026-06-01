import pytest
from unittest.mock import MagicMock, patch

from app.core.attacker_transport import (
    AttackerHost,
    ResolvedConnection,
    require_attacker_ssh,
    _cred_matches_host,
    build_ssh_config_from_cred,
    list_global_targets_for_project,
    _find_global_target_by_id,
    _find_exec_target_by_id,
    _resolve_exec_project_ssh,
    _resolve_exec_global_ssh,
    resolve_exec_ssh_configs,
)


class TestAttackerHost:
    def test_basic(self):
        h = MagicMock()
        ah = AttackerHost(host=h)
        assert ah.host == h
        assert ah.cred is None


class TestResolvedConnection:
    def test_basic(self):
        rc = ResolvedConnection(ssh_config={"host": "10.0.0.1"})
        assert rc.ssh_config == {"host": "10.0.0.1"}
        assert rc.candidates == []
        assert rc.attacker_host is None


class TestRequireAttackerSsh:
    def test_disabled(self):
        from fastapi import HTTPException
        with patch("app.core.attacker_transport.registry") as mock_reg:
            mock_reg.get.return_value = None
            with pytest.raises(HTTPException) as exc:
                require_attacker_ssh()
            assert exc.value.status_code == 404

    def test_enabled(self):
        with patch("app.core.attacker_transport.registry") as mock_reg:
            m = MagicMock()
            m.enabled = True
            mock_reg.get.return_value = m
            require_attacker_ssh()


class TestCredMatchesHost:
    def test_host_ids_match(self):
        cred = MagicMock()
        cred.host_ids = ["h1"]
        cred.host = ""
        host = MagicMock()
        host.id = "h1"
        assert _cred_matches_host(cred, host) is True

    def test_ip_match(self):
        cred = MagicMock()
        cred.host_ids = []
        cred.host = "10.0.0.1"
        host = MagicMock()
        host.id = "h1"
        host.ip = "10.0.0.1"
        host.hostname = ""
        assert _cred_matches_host(cred, host) is True

    def test_no_match(self):
        cred = MagicMock()
        cred.host_ids = []
        cred.host = "10.0.0.99"
        host = MagicMock()
        host.id = "h1"
        host.ip = "10.0.0.1"
        host.hostname = ""
        assert _cred_matches_host(cred, host) is False


class TestBuildSshConfigFromCred:
    def test_plain(self):
        host = MagicMock()
        host.ip = "10.0.0.1"
        cred = MagicMock()
        cred.secret = ""
        cred.username = "admin"
        cred.type = "plain"
        with patch("app.core.attacker_transport.decrypt_str", return_value="pass"):
            result = build_ssh_config_from_cred(host, cred)
            assert result["host"] == "10.0.0.1"
            assert result["username"] == "admin"
            assert result["password"] == "pass"

    def test_key(self):
        host = MagicMock()
        host.ip = "10.0.0.1"
        cred = MagicMock()
        cred.secret = ""
        cred.username = "root"
        cred.type = "key"
        with patch("app.core.attacker_transport.decrypt_str", return_value="key_data"):
            result = build_ssh_config_from_cred(host, cred)
            assert result["private_key"] == "key_data"
            assert result["password"] == ""

    def test_with_fallback(self):
        host = MagicMock()
        host.ip = "10.0.0.1"
        cred = MagicMock()
        cred.secret = ""
        cred.username = "u"
        cred.type = "plain"
        with patch("app.core.attacker_transport.decrypt_str", return_value="p"):
            result = build_ssh_config_from_cred(host, cred, {"port": 2222, "known_hosts_policy": "ignore"})
            assert result["port"] == 2222
            assert result["known_hosts_policy"] == "ignore"


class TestListGlobalTargetsForProject:
    def test_filters_by_project(self):
        with patch("app.core.attacker_transport.list_attacker_targets", return_value=[
            {"id": "t1", "enabled": True, "project_ids": ["p1"], "name": "T1", "host": "10.0.0.1", "port": 22, "username": "u"},
            {"id": "t2", "enabled": True, "project_ids": ["p2"], "name": "T2", "host": "10.0.0.2", "port": 22, "username": "u"},
            {"id": "t3", "enabled": True, "project_ids": [], "name": "T3", "host": "10.0.0.3", "port": 22, "username": "u"},
        ]):
            result = list_global_targets_for_project("p1")
            ids = [t["id"] for t in result]
            assert "t1" in ids
            assert "t2" not in ids
            assert "t3" in ids


class TestFindGlobalTargetById:
    def test_found(self):
        with patch("app.core.attacker_transport.list_attacker_targets", return_value=[
            {"id": "t1", "enabled": True},
        ]):
            assert _find_global_target_by_id("t1") is not None

    def test_not_found(self):
        with patch("app.core.attacker_transport.list_attacker_targets", return_value=[]):
            assert _find_global_target_by_id("t99") is None

    def test_disabled(self):
        with patch("app.core.attacker_transport.list_attacker_targets", return_value=[
            {"id": "t1", "enabled": False},
        ]):
            assert _find_global_target_by_id("t1") is None


class TestFindExecTargetById:
    def test_pivot_only(self):
        from fastapi import HTTPException
        with patch("app.core.attacker_transport.list_attacker_targets", return_value=[
            {"id": "t1", "enabled": True, "is_operator": False},
        ]):
            with pytest.raises(HTTPException) as exc:
                _find_exec_target_by_id("t1")
            assert "pivot" in str(exc.value.detail).lower()


class TestResolveExecProjectSsh:
    def test_no_host(self):
        db = MagicMock()
        q = MagicMock()
        db.query.return_value = q
        q.filter.return_value.first.return_value = None
        with patch("app.core.attacker_transport.models", create=True) as mock_models:
            mock_models.Host.id = "id"
            mock_models.Host.pid = "pid"
            result = _resolve_exec_project_ssh(db, "p1", "h1")
            assert result == []

    def test_no_cred(self):
        db = MagicMock()
        host = MagicMock()
        q = MagicMock()
        db.query.return_value = q
        q.filter.return_value.first.return_value = host
        with patch("app.core.attacker_transport.models", create=True) as mock_models, \
             patch("app.core.attacker_transport.resolve_project_ssh_cred", return_value=None):
            mock_models.Host.id = "id"
            mock_models.Host.pid = "pid"
            result = _resolve_exec_project_ssh(db, "p1", "h1")
            assert result == []


class TestResolveExecGlobalSsh:
    def test_no_target(self):
        with patch("app.core.attacker_transport._find_exec_target_by_id", return_value=None):
            result = _resolve_exec_global_ssh("t99")
            assert result == []

    def test_found(self):
        with patch("app.core.attacker_transport._find_exec_target_by_id", return_value={"host": "10.0.0.1"}):
            result = _resolve_exec_global_ssh("t1")
            assert len(result) == 1


class TestResolveExecSshConfigs:
    def test_by_host_id(self):
        with patch("app.core.attacker_transport._resolve_exec_project_ssh", return_value=[{"host": "10.0.0.1"}]):
            result = resolve_exec_ssh_configs(MagicMock(), "p1", attacker_host_id="h1")
            assert len(result) == 1

    def test_by_target_id(self):
        with patch("app.core.attacker_transport._resolve_exec_global_ssh", return_value=[{"host": "10.0.0.2"}]):
            result = resolve_exec_ssh_configs(MagicMock(), "p1", attacker_target_id="t1")
            assert len(result) == 1

    def test_auto(self):
        with patch("app.core.attacker_transport._resolve_exec_auto_ssh", return_value=[{"host": "10.0.0.3"}]):
            result = resolve_exec_ssh_configs(MagicMock(), "p1")
            assert len(result) == 1
