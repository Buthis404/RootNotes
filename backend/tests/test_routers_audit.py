"""Consolidated tests for test_routers_audit (merged variant files)."""

# ════════ from test_routers_audit_extended.py ════════
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


# ════════ from test_routers_audit_final.py ════════
import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from app.routers.audit import _parse_audit_log_line, _cross_reference_file_ids


class TestParseAuditLogLine:
    def test_empty_string(self):
        assert _parse_audit_log_line("") is None

    def test_whitespace_only(self):
        assert _parse_audit_log_line("   ") is None

    def test_valid_json(self):
        result = _parse_audit_log_line('{"id": "evt1", "action": "create"}')
        assert result == {"id": "evt1", "action": "create"}

    def test_invalid_json(self):
        assert _parse_audit_log_line("not json at all") is None

    def test_stripped_json(self):
        result = _parse_audit_log_line('  {"id": "x"}  ')
        assert result == {"id": "x"}


class TestCrossReferenceFileIds:
    def test_empty_file(self, tmp_path):
        log_path = tmp_path / "test.jsonl"
        log_path.write_text("")
        result = _cross_reference_file_ids(log_path, None, set())
        assert result == []

    def test_file_only_ids(self, tmp_path):
        log_path = tmp_path / "test.jsonl"
        log_path.write_text('{"id": "e1", "pid": "p1"}\n{"id": "e2", "pid": "p1"}\n')
        result = _cross_reference_file_ids(log_path, "p1", {"e1"})
        assert result == ["e2"]

    def test_pid_filter(self, tmp_path):
        log_path = tmp_path / "test.jsonl"
        log_path.write_text('{"id": "e1", "pid": "p1"}\n{"id": "e2", "pid": "p2"}\n')
        result = _cross_reference_file_ids(log_path, "p1", set())
        assert result == ["e1"]

    def test_missing_file(self, tmp_path):
        log_path = tmp_path / "nonexistent.jsonl"
        result = _cross_reference_file_ids(log_path, None, set())
        assert result == []

    def test_malformed_lines_skipped(self, tmp_path):
        log_path = tmp_path / "test.jsonl"
        log_path.write_text("bad line\n{\"id\": \"e1\"}\n")
        result = _cross_reference_file_ids(log_path, None, set())
        assert result == ["e1"]


class TestAuditAPIEndpoints:
    @pytest.fixture(scope="module", autouse=True)
    def _setup(self, module_client):
        module_client.post("/api/auth/setup", json={"username": "admin", "password": "TestPass1234!"})
        r = module_client.post("/api/auth/login", json={"username": "admin", "password": "TestPass1234!"})
        assert r.status_code == 200, f"login: {r.status_code} {r.text}"
        yield

    def test_status_returns_s3_fields(self, module_client):
        r = module_client.get("/api/admin/audit/status")
        assert r.status_code == 200
        data = r.json()
        assert "s3_bucket_configured" in data
        assert "s3_bucket" in data

    def test_verify_no_key_returns_note(self, module_client):
        r = module_client.get("/api/admin/audit/verify")
        assert r.status_code == 200
        data = r.json()
        assert "file_only" in data
        assert data["ok"] is True
