"""Extended BloodHound import tests — parser paths and edge cases."""
import io
import json
import zipfile
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
TS = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    r = module_client.post("/api/projects", json={"name": "BHExtTest", "added": TS, "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]
    yield


class TestBHParsers:
    def test_host_short(self):
        from app.routers.import_bloodhound import _host_short
        assert _host_short("DC01.CORP.LOCAL") == "DC01"
        assert _host_short("") == ""
        assert _host_short("SIMPLE") == "SIMPLE"

    def test_user_short(self):
        from app.routers.import_bloodhound import _user_short
        assert _user_short("admin@corp.local") == "admin"
        assert _user_short("USER") == "user"

    def test_get_items_old_format(self):
        from app.routers.import_bloodhound import _get_items
        data = {"computers": [{"name": "PC1"}]}
        result = _get_items(data)
        assert len(result) == 1

    def test_get_items_new_format(self):
        from app.routers.import_bloodhound import _get_items
        data = {"data": [{"name": "PC1"}]}
        result = _get_items(data)
        assert len(result) == 1

    def test_get_items_empty(self):
        from app.routers.import_bloodhound import _get_items
        assert _get_items({}) == []

    def test_add_host_tag(self):
        from app.routers.import_bloodhound import _add_host_tag
        host = MagicMock()
        host.tags = ["existing"]
        changed = _add_host_tag(host, "new_tag")
        assert changed is True
        assert "new_tag" in host.tags

    def test_add_host_tag_duplicate(self):
        from app.routers.import_bloodhound import _add_host_tag
        host = MagicMock()
        host.tags = ["existing"]
        changed = _add_host_tag(host, "existing")
        assert changed is False


class TestBHAddEdge:
    def test_adds_edge(self):
        from app.routers.import_bloodhound import _bh_add_edge
        seen = set()
        edges = []
        _bh_add_edge(seen, edges, "h1", "h2", "smb_admin", "LocalAdmin")
        assert len(edges) == 1
        assert edges[0]["type"] == "smb_admin"

    def test_skips_self_edge(self):
        from app.routers.import_bloodhound import _bh_add_edge
        seen = set()
        edges = []
        _bh_add_edge(seen, edges, "h1", "h1", "smb_admin", "LocalAdmin")
        assert len(edges) == 0

    def test_deduplicates(self):
        from app.routers.import_bloodhound import _bh_add_edge
        seen = set()
        edges = []
        _bh_add_edge(seen, edges, "h1", "h2", "smb_admin", "LocalAdmin")
        _bh_add_edge(seen, edges, "h1", "h2", "smb_admin", "LocalAdmin")
        assert len(edges) == 1

    def test_skips_empty_ids(self):
        from app.routers.import_bloodhound import _bh_add_edge
        seen = set()
        edges = []
        _bh_add_edge(seen, edges, "", "h2", "smb_admin", "LocalAdmin")
        assert len(edges) == 0


class TestBHDCDetection:
    def test_dc_by_role(self):
        from app.routers.import_bloodhound import _bh_dc_or_tag
        h = MagicMock()
        h.role = "domain_controller"
        h.tags = []
        assert _bh_dc_or_tag(h) is True

    def test_dc_by_tag(self):
        from app.routers.import_bloodhound import _bh_dc_or_tag
        h = MagicMock()
        h.role = "server"
        h.tags = ["dc"]
        assert _bh_dc_or_tag(h) is True

    def test_not_dc(self):
        from app.routers.import_bloodhound import _bh_dc_or_tag
        h = MagicMock()
        h.role = "workstation"
        h.tags = []
        assert _bh_dc_or_tag(h) is False


class TestBHTrustTypeDir:
    def test_trust_type_dir(self):
        from app.routers.import_bloodhound import _bh_trust_type_dir
        t_type, t_dir = _bh_trust_type_dir({"TrustType": 0, "TrustDirection": 3})
        assert t_type == "ParentChild"
        assert t_dir == "Bidirectional"

    def test_trust_type_dir_string(self):
        from app.routers.import_bloodhound import _bh_trust_type_dir
        t_type, t_dir = _bh_trust_type_dir({"TrustType": "Custom", "TrustDirection": "Inbound"})
        assert t_type == "Custom"
        assert t_dir == "Inbound"


class TestBHProcessAce:
    def test_processes_acl_edge(self):
        from app.routers.import_bloodhound import _bh_process_ace
        db = MagicMock()
        ace = {"RightName": "GenericAll", "PrincipalSID": "S-1-5-21-1001"}
        seen = set()
        edges = []
        stats = {"acl_edges": 0}
        sid_to_hid = {"S-1-5-21-1001": "h1"}
        sid_to_cid = {}
        _bh_process_ace(db, ace, "h2", sid_to_hid, sid_to_cid, seen, edges, stats)
        assert stats["acl_edges"] == 1

    def test_unknown_right_skipped(self):
        from app.routers.import_bloodhound import _bh_process_ace
        db = MagicMock()
        ace = {"RightName": "UnknownRight", "PrincipalSID": "S-1"}
        seen = set()
        edges = []
        stats = {"acl_edges": 0}
        _bh_process_ace(db, ace, "h2", {"S-1": "h1"}, {}, seen, edges, stats)
        assert stats["acl_edges"] == 0


class TestBHParseJsonFile:
    def test_parse_json_file(self, module_client: TestClient):
        computers_data = {
            "data": [{
                "Properties": {
                    "name": "PC01.CORP.LOCAL",
                    "objectid": "S-1-5-21-1-3001",
                    "operatingsystem": "Windows 10",
                    "domain": "corp.local",
                },
                "LocalAdmins": {"Results": []},
                "Sessions": {"Results": []},
                "Aces": [],
                "AllowedToDelegate": [],
                "CanRDP": [],
            }]
        }
        r = module_client.post(
            f"/api/projects/{_state['pid']}/import/bloodhound",
            files={"file": ("test_computers.json", json.dumps(computers_data).encode(), "application/json")},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["hosts_created"] >= 1


class TestBHImportGroups:
    def test_import_groups_resolves_da(self, module_client: TestClient):
        groups_data = {
            "data": [{
                "Properties": {
                    "name": "DOMAIN ADMINS@CORP.LOCAL",
                    "objectid": "S-1-5-21-1-512",
                    "domain": "corp.local",
                },
                "Members": [{"ObjectIdentifier": "S-1-5-21-1-2001"}],
            }]
        }
        r = module_client.post(
            f"/api/projects/{_state['pid']}/import/bloodhound",
            files={"file": ("test_groups.json", json.dumps(groups_data).encode(), "application/json")},
        )
        assert r.status_code == 200


class TestBHImportInvalidFile:
    def test_unsupported_file_type(self, module_client: TestClient):
        r = module_client.post(
            f"/api/projects/{_state['pid']}/import/bloodhound",
            files={"file": ("test.txt", b"hello", "text/plain")},
        )
        assert r.status_code == 400

    def test_invalid_zip(self, module_client: TestClient):
        r = module_client.post(
            f"/api/projects/{_state['pid']}/import/bloodhound",
            files={"file": ("test.zip", b"not a zip", "application/zip")},
        )
        assert r.status_code == 400

    def test_invalid_json(self, module_client: TestClient):
        r = module_client.post(
            f"/api/projects/{_state['pid']}/import/bloodhound",
            files={"file": ("test_users.json", b"not json", "application/json")},
        )
        assert r.status_code == 400
