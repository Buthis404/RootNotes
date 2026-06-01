"""
Tests for BloodHound import endpoints.
"""

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
