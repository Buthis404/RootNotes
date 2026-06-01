import pytest
from unittest.mock import MagicMock, patch

from app.routers.import_export import (
    _merge_host_identity,
    _merge_existing_host,
    _prepare_host_data,
    _import_networks,
    _import_activities_and_paths,
    _import_loots_and_scope,
)


class TestMergeHostIdentityMore:
    def test_keeps_existing(self):
        host = MagicMock()
        host.hostname = "existing"
        host.domain = "corp"
        host.role = "server"
        host.is_attacker = False
        host.ip = "10.0.0.1"
        _merge_host_identity(host, {"hostname": "new", "domain": "new"})
        assert host.hostname == "existing"

    def test_fills_ip(self):
        host = MagicMock()
        host.hostname = ""
        host.domain = ""
        host.role = "unknown"
        host.is_attacker = False
        host.ip = ""
        _merge_host_identity(host, {"ip": "10.0.0.1"})
        assert host.ip == "10.0.0.1"


class TestMergeExistingHostMore:
    def test_keeps_higher_status(self):
        host = MagicMock()
        host.ips = []
        host.ports = []
        host.services = []
        host.tags = []
        host.hostname = ""
        host.domain = ""
        host.role = "unknown"
        host.is_attacker = False
        host.ip = ""
        host.os = "Unknown"
        host.notes = ""
        host.status = "pwned"
        rank = {"unknown": 0, "up": 1, "pwned": 4}
        _merge_existing_host(host, {"status": "up", "ports": [], "services": [], "tags": []}, rank)
        assert host.status == "pwned"

    def test_adds_ips(self):
        host = MagicMock()
        host.ips = []
        host.ports = []
        host.services = []
        host.tags = []
        host.hostname = ""
        host.domain = ""
        host.role = "unknown"
        host.is_attacker = False
        host.ip = ""
        host.os = "Unknown"
        host.notes = ""
        host.status = "unknown"
        rank = {"unknown": 0}
        _merge_existing_host(host, {"ips": ["10.0.0.1", "10.0.0.2"], "ports": [], "services": [], "tags": []}, rank)
        assert len(host.ips) == 2

    def test_keeps_existing_hostname(self):
        host = MagicMock()
        host.ips = []
        host.ports = []
        host.services = []
        host.tags = []
        host.hostname = "existing"
        host.domain = ""
        host.role = "unknown"
        host.is_attacker = False
        host.ip = ""
        host.os = "Unknown"
        host.notes = ""
        host.status = "unknown"
        rank = {"unknown": 0}
        _merge_existing_host(host, {"hostname": "new", "ports": [], "services": [], "tags": []}, rank)
        assert host.hostname == "existing"


class TestPrepareHostDataMore:
    def test_non_attacker(self):
        from app.routers.import_export import _prepare_host_data
        h = MagicMock()
        h.model_dump.return_value = {"ip": "10.0.0.1", "hostname": "srv",
                                      "is_attacker": False, "role": "server",
                                      "status": "up"}
        data, ip, hn = _prepare_host_data(h, "p1")
        assert ip == "10.0.0.1"

    def test_no_ip(self):
        from app.routers.import_export import _prepare_host_data
        h = MagicMock()
        h.model_dump.return_value = {"ip": "", "hostname": "srv",
                                      "is_attacker": False, "role": ""}
        data, ip, hn = _prepare_host_data(h, "p1")
        assert ip == ""


class TestImportNetworksMore:
    def test_empty(self):
        db = MagicMock()
        _import_networks(db, "p1", [])
        assert db.add.call_count == 0

    def test_with_all_data(self):
        db = MagicMock()
        with patch("app.routers.import_export.new_id", return_value="net1"):
            with patch("app.routers.import_export.replace_nodes"):
                with patch("app.routers.import_export.replace_edges"):
                    with patch("app.routers.import_export.replace_regions"):
                        _import_networks(db, "p1", [{
                            "name": "Net1", "nodes": [{"id": "n1", "x": 100, "y": 200}],
                            "edges": [{"id": "e1", "from": "n1", "to": "n2"}],
                            "regions": [{"id": "r1", "label": "DMZ"}],
                        }])
                        assert db.add.called


class TestImportActivitiesMore:
    def test_empty(self):
        db = MagicMock()
        _import_activities_and_paths(db, "p1", [], [], [], [], [], {})
        assert db.add.call_count == 0

    def test_finding_without_host(self):
        db = MagicMock()
        with patch("app.routers.import_export.new_id", return_value="id1"):
            _import_activities_and_paths(db, "p1",
                                          [{"title": "f1", "host_id": None}],
                                          [], [], [], [], {})
