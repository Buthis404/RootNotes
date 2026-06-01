"""Audit API integration tests — status and verify endpoints."""
import pytest
from fastapi.testclient import TestClient

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200, r.text
    yield
    module_client.post("/api/auth/logout")


class TestAuditStatus:
    def test_audit_status(self, module_client: TestClient):
        r = module_client.get("/api/admin/audit/status")
        assert r.status_code == 200
        data = r.json()
        assert "integrity_key_configured" in data
        assert "db_event_count" in data
        assert "db_signed_event_count" in data
        assert "db_unsigned_event_count" in data
        assert "log_file" in data

    def test_audit_status_fields_types(self, module_client: TestClient):
        r = module_client.get("/api/admin/audit/status")
        data = r.json()
        assert isinstance(data["integrity_key_configured"], bool)
        assert isinstance(data["db_event_count"], int)


class TestAuditVerify:
    def test_audit_verify(self, module_client: TestClient):
        r = module_client.get("/api/admin/audit/verify")
        assert r.status_code == 200
        data = r.json()
        assert "ok" in data
        assert "checked" in data
        assert "tampered" in data
        assert "unverified" in data

    def test_audit_verify_with_limit(self, module_client: TestClient):
        r = module_client.get("/api/admin/audit/verify?limit=10")
        assert r.status_code == 200
        data = r.json()
        assert data["checked"] <= 10

    def test_audit_verify_with_pid(self, module_client: TestClient):
        r = module_client.get("/api/admin/audit/verify?pid=prj_nonexistent")
        assert r.status_code == 200
        assert r.json()["checked"] == 0


class TestAuditUnauthenticated:
    def test_status_requires_auth(self, module_client: TestClient):
        module_client.post("/api/auth/logout")
        r = module_client.get("/api/admin/audit/status")
        assert r.status_code == 401
        module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})

    def test_verify_requires_auth(self, module_client: TestClient):
        module_client.post("/api/auth/logout")
        r = module_client.get("/api/admin/audit/verify")
        assert r.status_code == 401
        module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
