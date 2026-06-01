"""Consolidated tests for test_import_bloodhound (merged variant files)."""

# ════════ from test_import_bloodhound_api.py ════════
import io
import json
import zipfile
import pytest
from datetime import datetime, timezone
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
    r = module_client.post("/api/projects", json={"name": "BHImportTest", "added": TS, "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]
    yield
    module_client.post("/api/auth/logout")


COMPUTERS_JSON = {
    "data": [
        {
            "Properties": {
                "name": "DC01.CORP.LOCAL",
                "objectid": "S-1-5-21-1-1001",
                "operatingsystem": "Windows Server 2022",
                "unconstraineddelegation": True,
                "domain": "corp.local",
            },
            "LocalAdmins": {"Results": []},
            "Sessions": {"Results": []},
            "Aces": [],
            "AllowedToDelegate": [],
            "CanRDP": [],
        },
        {
            "Properties": {
                "name": "WS01.CORP.LOCAL",
                "objectid": "S-1-5-21-1-1002",
                "operatingsystem": "Windows 10",
                "domain": "corp.local",
            },
            "LocalAdmins": {
                "Results": [
                    {"ObjectIdentifier": "S-1-5-21-1-2001"}
                ]
            },
            "Sessions": {"Results": []},
            "Aces": [],
            "AllowedToDelegate": [],
            "CanRDP": [],
        },
    ]
}

USERS_JSON = {
    "data": [
        {
            "Properties": {
                "name": "admin@corp.local",
                "objectid": "S-1-5-21-1-2001",
                "domain": "corp.local",
                "admincount": True,
                "serviceprincipalnames": [],
                "samaccountname": "admin",
            },
        },
        {
            "Properties": {
                "name": "jdoe@corp.local",
                "objectid": "S-1-5-21-1-2002",
                "domain": "corp.local",
                "admincount": False,
                "serviceprincipalnames": [],
                "samaccountname": "jdoe",
            },
        },
    ]
}

GROUPS_JSON = {
    "data": [
        {
            "Properties": {
                "name": "DOMAIN ADMINS@CORP.LOCAL",
                "objectid": "S-1-5-21-1-512",
                "domain": "corp.local",
            },
            "Members": [
                {"ObjectIdentifier": "S-1-5-21-1-2001"},
            ],
        },
    ]
}

SESSIONS_JSON = {
    "data": [],
}


def _make_bh_zip(computers=None, users=None, groups=None, sessions=None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("20240101_computers.json", json.dumps(computers or COMPUTERS_JSON))
        zf.writestr("20240101_users.json", json.dumps(users or USERS_JSON))
        zf.writestr("20240101_groups.json", json.dumps(groups or GROUPS_JSON))
        zf.writestr("20240101_sessions.json", json.dumps(sessions or SESSIONS_JSON))
    return buf.getvalue()


class TestBloodhoundImportZip:
    def test_import_zip(self, module_client: TestClient):
        data = _make_bh_zip()
        r = module_client.post(
            f"/api/projects/{_state['pid']}/import/bloodhound",
            files={"file": ("bh.zip", data, "application/zip")},
        )
        assert r.status_code == 200, r.text
        result = r.json()
        assert result["hosts_created"] >= 1
        assert result["creds_created"] >= 1

    def test_import_preserves_hosts(self, module_client: TestClient):
        r = module_client.get("/api/hosts", params={"pid": _state["pid"]})
        assert r.status_code == 200
        hostnames = [h["hostname"] for h in r.json()]
        assert "DC01" in hostnames

    def test_import_preserves_creds(self, module_client: TestClient):
        r = module_client.get("/api/creds", params={"pid": _state["pid"]})
        assert r.status_code == 200
        usernames = [c["username"] for c in r.json()]
        assert "admin" in usernames


class TestBloodhoundImportJson:
    def test_import_computers_json(self, module_client: TestClient):
        r = module_client.post(
            f"/api/projects/{_state['pid']}/import/bloodhound",
            files={"file": ("computers.json", json.dumps(COMPUTERS_JSON).encode(), "application/json")},
        )
        assert r.status_code == 200, r.text

    def test_import_users_json(self, module_client: TestClient):
        r = module_client.post(
            f"/api/projects/{_state['pid']}/import/bloodhound",
            files={"file": ("users.json", json.dumps(USERS_JSON).encode(), "application/json")},
        )
        assert r.status_code == 200, r.text


class TestBloodhoundImportErrors:
    def test_unsupported_file_type(self, module_client: TestClient):
        r = module_client.post(
            f"/api/projects/{_state['pid']}/import/bloodhound",
            files={"file": ("data.txt", b"not valid", "text/plain")},
        )
        assert r.status_code == 400

    def test_invalid_zip(self, module_client: TestClient):
        r = module_client.post(
            f"/api/projects/{_state['pid']}/import/bloodhound",
            files={"file": ("bad.zip", b"not a zip", "application/zip")},
        )
        assert r.status_code == 400

    def test_zip_no_bh_files(self, module_client: TestClient):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("readme.txt", "nothing here")
        r = module_client.post(
            f"/api/projects/{_state['pid']}/import/bloodhound",
            files={"file": ("empty.zip", buf.getvalue(), "application/zip")},
        )
        assert r.status_code == 400


class TestBloodhoundHelpers:
    def test_host_short(self):
        from app.routers.import_bloodhound import _host_short
        assert _host_short("DC01.CORP.LOCAL") == "DC01"
        assert _host_short("") == ""

    def test_user_short(self):
        from app.routers.import_bloodhound import _user_short
        assert _user_short("admin@corp.local") == "admin"
        assert _user_short("") == ""

    def test_get_items(self):
        from app.routers.import_bloodhound import _get_items
        assert _get_items({"data": [1, 2]}) == [1, 2]
        assert _get_items({"computers": [3]}) == [3]
        assert _get_items({}) == []

    def test_bh_build_index(self):
        from app.routers.import_bloodhound import _bh_build_index

        class FakeHost:
            hostname = "DC01"
            ip = "10.0.0.1"

        class FakeCred:
            username = "admin"
            service = "AD"

        h_by_hn, c_by_un = _bh_build_index([FakeHost()], [FakeCred()])
        assert "DC01" in h_by_hn
        assert "admin" in c_by_un


# ════════ from test_import_bloodhound_extended.py ════════
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


# ════════ from test_import_bloodhound_extra.py ════════
import io
import json
import zipfile
import pytest
from unittest.mock import MagicMock, patch

from app.routers.import_bloodhound import (
    _host_short,
    _user_short,
    _get_items,
    _bh_trust_type_dir,
    _bh_add_edge,
    _add_host_tag,
    _bh_dc_or_tag,
    _bh_build_index,
)


class TestHostShort:
    def test_fqdn(self):
        assert _host_short("SDOTSON.EDU.STF") == "SDOTSON"

    def test_single(self):
        assert _host_short("PC1") == "PC1"

    def test_empty(self):
        assert _host_short("") == ""


class TestUserShort:
    def test_upn(self):
        assert _user_short("S_DOTSON@EDU.STF") == "s_dotson"

    def test_plain(self):
        assert _user_short("admin") == "admin"

    def test_empty(self):
        assert _user_short("") == ""


class TestGetItems:
    def test_data_key(self):
        assert _get_items({"data": [{"id": 1}]}) == [{"id": 1}]

    def test_computers_key(self):
        assert _get_items({"computers": [{"id": 2}]}) == [{"id": 2}]

    def test_users_key(self):
        assert _get_items({"users": [{"id": 3}]}) == [{"id": 3}]

    def test_groups_key(self):
        assert _get_items({"groups": [{"id": 4}]}) == [{"id": 4}]

    def test_sessions_key(self):
        assert _get_items({"sessions": [{"id": 5}]}) == [{"id": 5}]

    def test_no_match(self):
        assert _get_items({}) == []


class TestBhTrustTypeDir:
    def test_types(self):
        t, d = _bh_trust_type_dir({"TrustType": 0, "TrustDirection": 3})
        assert t == "ParentChild"
        assert d == "Bidirectional"

    def test_string_values(self):
        t, d = _bh_trust_type_dir({"TrustType": "Custom", "TrustDirection": "Outbound"})
        assert t == "Custom"
        assert d == "Outbound"


class TestBhAddEdge:
    def test_basic(self):
        edges = []
        seen = set()
        result = _bh_add_edge(seen, edges, "h1", "h2", "ssh", "SSH")
        assert result is True
        assert len(edges) == 1

    def test_duplicate(self):
        edges = []
        seen = set()
        _bh_add_edge(seen, edges, "h1", "h2", "ssh", "SSH")
        result = _bh_add_edge(seen, edges, "h1", "h2", "ssh", "SSH")
        assert result is False

    def test_self_edge(self):
        edges = []
        seen = set()
        result = _bh_add_edge(seen, edges, "h1", "h1", "ssh", "SSH")
        assert result is False

    def test_empty_ids(self):
        edges = []
        seen = set()
        result = _bh_add_edge(seen, edges, "", "h2", "ssh", "SSH")
        assert result is False


class TestAddHostTag:
    def test_new_tag(self):
        host = MagicMock()
        host.tags = ["existing"]
        result = _add_host_tag(host, "new_tag")
        assert result is True
        assert "new_tag" in host.tags

    def test_existing_tag(self):
        host = MagicMock()
        host.tags = ["existing"]
        result = _add_host_tag(host, "existing")
        assert result is False


class TestBhDcOrTag:
    def test_dc_role(self):
        h = MagicMock()
        h.role = "domain_controller"
        h.tags = []
        assert _bh_dc_or_tag(h) is True

    def test_dc_tag(self):
        h = MagicMock()
        h.role = ""
        h.tags = ["dc"]
        assert _bh_dc_or_tag(h) is True

    def test_not_dc(self):
        h = MagicMock()
        h.role = "server"
        h.tags = ["web"]
        assert _bh_dc_or_tag(h) is False


class TestBhBuildIndex:
    def test_basic(self):
        h1 = MagicMock()
        h1.hostname = "PC1"
        h2 = MagicMock()
        h2.hostname = "PC2"
        c1 = MagicMock()
        c1.username = "admin"
        c1.service = "AD"
        hn, cr = _bh_build_index([h1, h2], [c1])
        assert "PC1" in hn
        assert "admin" in cr
