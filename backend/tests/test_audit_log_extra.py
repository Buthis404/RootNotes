import pytest
from unittest.mock import patch, MagicMock

from app.core.audit_log import (
    compute_integrity,
    verify_integrity,
    append_to_file,
    persist,
    _INTEGRITY_FIELDS,
)


class TestComputeIntegrity:
    def test_with_key(self, monkeypatch):
        monkeypatch.setenv("AUDIT_INTEGRITY_KEY", "testkey123")
        import importlib
        import app.core.audit_log as mod
        importlib.reload(mod)
        event = {"id": "e1", "pid": "p1", "entity": "host", "action": "create", "label": "test", "ts": "2024-01-01"}
        r = mod.compute_integrity(event)
        assert r is not None
        assert r.startswith("sha256=")

    def test_without_key(self, monkeypatch):
        monkeypatch.delenv("AUDIT_INTEGRITY_KEY", raising=False)
        import importlib
        import app.core.audit_log as mod
        importlib.reload(mod)
        event = {"id": "e1", "pid": "p1", "entity": "host", "action": "create", "label": "test", "ts": "2024-01-01"}
        assert mod.compute_integrity(event) is None


class TestVerifyIntegrity:
    def test_valid(self, monkeypatch):
        monkeypatch.setenv("AUDIT_INTEGRITY_KEY", "testkey123")
        import importlib
        import app.core.audit_log as mod
        importlib.reload(mod)
        event = {"id": "e1", "pid": "p1", "entity": "host", "action": "create", "label": "test", "ts": "2024-01-01"}
        event["integrity"] = mod.compute_integrity(event)
        assert mod.verify_integrity(event) is True

    def test_tampered(self, monkeypatch):
        monkeypatch.setenv("AUDIT_INTEGRITY_KEY", "testkey123")
        import importlib
        import app.core.audit_log as mod
        importlib.reload(mod)
        event = {"id": "e1", "pid": "p1", "entity": "host", "action": "create", "label": "test", "ts": "2024-01-01"}
        event["integrity"] = "sha256=bad"
        assert mod.verify_integrity(event) is False

    def test_no_key(self, monkeypatch):
        monkeypatch.delenv("AUDIT_INTEGRITY_KEY", raising=False)
        import importlib
        import app.core.audit_log as mod
        importlib.reload(mod)
        assert mod.verify_integrity({"integrity": "sha256=abc"}) is None

    def test_no_stored(self, monkeypatch):
        monkeypatch.setenv("AUDIT_INTEGRITY_KEY", "testkey123")
        import importlib
        import app.core.audit_log as mod
        importlib.reload(mod)
        assert mod.verify_integrity({}) is None


class TestAppendToFile:
    def test_basic(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AUDIT_LOG_DIR", str(tmp_path / "audit"))
        import importlib
        import app.core.audit_log as mod
        importlib.reload(mod)
        event = {"id": "e1", "action": "create"}
        mod.append_to_file(event)
        log_file = tmp_path / "audit" / "timeline.jsonl"
        assert log_file.exists()
        content = log_file.read_text()
        assert "e1" in content


class TestPersist:
    def test_persist_no_s3(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AUDIT_LOG_DIR", str(tmp_path / "audit"))
        monkeypatch.setenv("AUDIT_S3_BUCKET", "")
        import importlib
        import app.core.audit_log as mod
        importlib.reload(mod)
        event = {"id": "e2", "action": "update"}
        mod.persist(event)
        log_file = tmp_path / "audit" / "timeline.jsonl"
        assert log_file.exists()
