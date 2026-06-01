"""Extended hosts tests — bulk import, attacker hosts, edge cases."""
import pytest
from fastapi.testclient import TestClient

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    r = module_client.post("/api/projects", json={"name": "HostExtTest", "added": "2025-01-01T00:00:00Z", "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]
    yield


class TestHostBulkImport:
    def test_bulk_import_single(self, module_client: TestClient):
        r = module_client.post(
            "/api/hosts/bulk",
            json={"pid": _state["pid"], "text": "10.200.200.1", "tags": ["bulk"], "os": "Linux", "status": "alive"},
        )
        assert r.status_code == 201
        data = r.json()
        assert data["created"] == 1

    def test_bulk_import_cidr(self, module_client: TestClient):
        r = module_client.post(
            "/api/hosts/bulk",
            json={"pid": _state["pid"], "text": "10.200.201.1-10.200.201.3", "os": "Windows"},
        )
        assert r.status_code in (201, 400)

    def test_bulk_import_invalid(self, module_client: TestClient):
        r = module_client.post(
            "/api/hosts/bulk",
            json={"pid": _state["pid"], "text": "not-an-ip"},
        )
        assert r.status_code == 400

    def test_bulk_import_duplicate_skip(self, module_client: TestClient):
        r = module_client.post(
            "/api/hosts/bulk",
            json={"pid": _state["pid"], "text": "10.200.200.1"},
        )
        assert r.status_code == 201
        assert r.json()["skipped"] == 1


class TestHostAttacker:
    def test_create_attacker_host(self, module_client: TestClient):
        r = module_client.post(
            "/api/hosts",
            json={
                "pid": _state["pid"],
                "ip": "10.99.99.99",
                "hostname": "attacker-host",
                "role": "attacker",
            },
        )
        assert r.status_code == 201
        data = r.json()
        assert data["is_attacker"] is True
        assert data["status"] == "attacker"
        _state["att_hid"] = data["id"]

    def test_update_host_to_attacker(self, module_client: TestClient):
        r = module_client.post(
            "/api/hosts",
            json={"pid": _state["pid"], "ip": "10.99.99.50"},
        )
        assert r.status_code == 201
        hid = r.json()["id"]
        r = module_client.patch(f"/api/hosts/{hid}", json={"is_attacker": True})
        assert r.status_code == 200
        assert r.json()["is_attacker"] is True


class TestHostDelete:
    def test_delete_host(self, module_client: TestClient):
        r = module_client.post(
            "/api/hosts",
            json={"pid": _state["pid"], "ip": "10.99.99.200"},
        )
        hid = r.json()["id"]
        r = module_client.delete(f"/api/hosts/{hid}")
        assert r.status_code == 204

    def test_delete_nonexistent(self, module_client: TestClient):
        r = module_client.delete("/api/hosts/nonexistent")
        assert r.status_code == 404


class TestExpandIps:
    def test_expand_helper(self):
        from app.routers.hosts import _expand_ips
        ips = _expand_ips("10.0.0.1, 10.0.0.2")
        assert len(ips) == 2

    def test_expand_cidr(self):
        from app.routers.hosts import _expand_ips
        ips = _expand_ips("10.0.0.252/30")
        assert len(ips) == 2
