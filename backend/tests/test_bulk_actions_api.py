"""
Tests for bulk action endpoints and helpers.
"""

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
    r = module_client.post("/api/projects", json={"name": "BulkTest", "added": TS, "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]

    r = module_client.post("/api/hosts", json={
        "pid": _state["pid"], "ip": "10.50.50.1", "hostname": "bulk-host1",
        "os": "Windows", "status": "alive",
    })
    assert r.status_code == 201
    _state["hid1"] = r.json()["id"]

    r = module_client.post("/api/hosts", json={
        "pid": _state["pid"], "ip": "10.50.50.2", "hostname": "bulk-host2",
        "os": "Linux", "status": "alive",
    })
    assert r.status_code == 201
    _state["hid2"] = r.json()["id"]

    r = module_client.post("/api/creds", json={
        "pid": _state["pid"], "username": "bulkadmin", "secret": "BulkPass!",
        "type": "plain", "host": "10.50.50.1",
    })
    assert r.status_code == 201
    _state["cid"] = r.json()["id"]

    yield
    module_client.post("/api/auth/logout")


class TestBulkExec:
    def test_bulk_exec_requires_module(self, module_client: TestClient):
        r = module_client.post(
            f"/api/projects/{_state['pid']}/bulk-exec",
            json={"host_ids": [_state["hid1"]], "command_template": "id"},
        )
        assert r.status_code in (404, 400, 422, 500)

    def test_bulk_exec_no_hosts(self, module_client: TestClient):
        r = module_client.post(
            f"/api/projects/{_state['pid']}/bulk-exec",
            json={"host_ids": [], "command_template": "id"},
        )
        assert r.status_code in (400, 404, 500)


class TestCredValidation:
    def test_validate_requires_module(self, module_client: TestClient):
        r = module_client.post(
            f"/api/projects/{_state['pid']}/creds/{_state['cid']}/validate",
            json={"host_ids": [_state["hid1"]], "service": "ssh"},
        )
        assert r.status_code in (404, 400, 422, 500)

    def test_validate_404_cred(self, module_client: TestClient):
        r = module_client.post(
            f"/api/projects/{_state['pid']}/creds/nonexistent/validate",
            json={"host_ids": [_state["hid1"]]},
        )
        assert r.status_code == 404


class TestCredMatrix:
    def test_get_cred_matrix(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/cred-matrix")
        assert r.status_code == 200
        data = r.json()
        assert "creds" in data
        assert "hosts" in data
        assert "matrix" in data


class TestBulkHelpers:
    def test_infer_bulk_access_role(self):
        from app.routers.bulk_actions import _infer_bulk_access_role
        assert _infer_bulk_access_role("evil-winrm foo") == "winrm"
        assert _infer_bulk_access_role("netexec mssql foo") == "database"
        assert _infer_bulk_access_role("sshpass -p x ssh foo") == "ssh"
        assert _infer_bulk_access_role("wmiexec foo") == "local_admin"
        assert _infer_bulk_access_role("echo hello") is None

    def test_auto_detect_service(self):
        from app.routers.bulk_actions import _auto_detect_service

        class Cred:
            service = "ssh"
            type = "plain"
            is_domain = False

        class Host:
            os = "Linux"

        assert _auto_detect_service("auto", Cred(), Host()) == "ssh"

    def test_auto_detect_service_smb(self):
        from app.routers.bulk_actions import _auto_detect_service

        class Cred:
            service = ""
            type = "ntlm"
            is_domain = True

        class Host:
            os = "Windows"

        assert _auto_detect_service("auto", Cred(), Host()) == "smb"

    def test_parse_validation_result_ssh(self):
        from app.routers.bulk_actions import _parse_validation_result
        assert _parse_validation_result(True, 0, "uid=0", "ssh") is True
        assert _parse_validation_result(True, 1, "error", "ssh") is False

    def test_parse_validation_result_smb(self):
        from app.routers.bulk_actions import _parse_validation_result
        assert _parse_validation_result(True, 0, "[+] pwn3d!", "smb") is True
        assert _parse_validation_result(True, 0, "[-] status_logon_failure", "smb") is False

    def test_validate_access_role(self):
        from app.routers.bulk_actions import _validate_access_role
        assert _validate_access_role("ssh", "uid=0(root)") == "local_admin"
        assert _validate_access_role("ssh", "uid=1000") == "ssh"
        assert _validate_access_role("smb", "pwn3d!") == "local_admin"
        assert _validate_access_role("rdp", "") == "rdp"

    def test_merge_list_field(self):
        from app.routers.bulk_actions import _merge_list_field
        result = _merge_list_field(["a", "b"], ["c"])
        assert set(result) == {"a", "b", "c"}
        assert _merge_list_field(["a"], []) is None
        assert _merge_list_field(None, ["a"]) is not None

    def test_maybe_promote_host_status(self):
        from app.routers.bulk_actions import _maybe_promote_host_status

        class H:
            status = "unknown"

        h = H()
        _maybe_promote_host_status(h, True)
        assert h.status == "access"

    def test_maybe_promote_host_status_no_promote(self):
        from app.routers.bulk_actions import _maybe_promote_host_status

        class H:
            status = "pwned"

        h = H()
        _maybe_promote_host_status(h, True)
        assert h.status == "pwned"

    def test_maybe_promote_host_status_failed(self):
        from app.routers.bulk_actions import _maybe_promote_host_status

        class H:
            status = "unknown"

        h = H()
        _maybe_promote_host_status(h, False)
        assert h.status == "unknown"
