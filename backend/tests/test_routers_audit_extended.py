"""Extended tests for audit — verify with data and cross-reference."""
import json
import os
import tempfile
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _setup(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    yield


class TestAuditVerifyWithLimit:
    def test_verify_limit_1(self, module_client: TestClient):
        r = module_client.get("/api/admin/audit/verify?limit=1")
        assert r.status_code == 200
        assert r.json()["checked"] <= 1

    def test_verify_no_key(self, module_client: TestClient):
        with patch("app.routers.audit._INTEGRITY_KEY", ""):
            r = module_client.get("/api/admin/audit/verify")
            assert r.status_code == 200
            data = r.json()
            assert data["ok"] is True
            assert "note" in data


class TestAuditStatusDetails:
    def test_status_fields(self, module_client: TestClient):
        r = module_client.get("/api/admin/audit/status")
        data = r.json()
        assert isinstance(data.get("log_file_exists"), bool)
        assert isinstance(data.get("s3_bucket_configured"), bool)
