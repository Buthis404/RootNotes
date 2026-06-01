"""Tests for app.core.audit_log — integrity, file append, S3 forward."""
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from app.core.audit_log import (
    append_to_file,
    compute_integrity,
    forward_to_s3,
    persist,
    verify_integrity,
)


class TestComputeIntegrity:
    def test_returns_none_without_key(self):
        with patch("app.core.audit_log._INTEGRITY_KEY", ""):
            event = {"id": "1", "pid": "p1", "entity": "host", "action": "create", "label": "", "ts": ""}
            assert compute_integrity(event) is None

    def test_returns_hmac_with_key(self):
        with patch("app.core.audit_log._INTEGRITY_KEY", "testsecret"):
            event = {"id": "1", "pid": "p1", "entity": "host", "action": "create", "label": "test", "ts": "2024-01-01"}
            result = compute_integrity(event)
            assert result is not None
            assert result.startswith("sha256=")
            assert len(result) > 10


class TestVerifyIntegrity:
    def test_returns_none_without_key(self):
        with patch("app.core.audit_log._INTEGRITY_KEY", ""):
            assert verify_integrity({"integrity": "sha256=abc"}) is None

    def test_returns_none_without_integrity_field(self):
        with patch("app.core.audit_log._INTEGRITY_KEY", "secret"):
            assert verify_integrity({}) is None

    def test_returns_true_when_valid(self):
        with patch("app.core.audit_log._INTEGRITY_KEY", "secret"):
            event = {"id": "1", "pid": "p1", "entity": "host", "action": "create", "label": "", "ts": ""}
            sig = compute_integrity(event)
            event["integrity"] = sig
            assert verify_integrity(event) is True

    def test_returns_false_when_tampered(self):
        with patch("app.core.audit_log._INTEGRITY_KEY", "secret"):
            event = {"id": "1", "pid": "p1", "entity": "host", "action": "create", "label": "", "ts": ""}
            sig = compute_integrity(event)
            event["integrity"] = sig
            event["label"] = "tampered"
            assert verify_integrity(event) is False


class TestAppendToFile:
    def test_writes_jsonl(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("app.core.audit_log._LOG_DIR", tmpdir):
                event = {"id": "ev1", "action": "test"}
                append_to_file(event)
                log_path = Path(tmpdir) / "timeline.jsonl"
                assert log_path.exists()
                lines = log_path.read_text().strip().splitlines()
                assert len(lines) >= 1
                parsed = json.loads(lines[-1])
                assert parsed["id"] == "ev1"

    def test_appends_multiple(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("app.core.audit_log._LOG_DIR", tmpdir):
                append_to_file({"id": "e1"})
                append_to_file({"id": "e2"})
                log_path = Path(tmpdir) / "timeline.jsonl"
                lines = log_path.read_text().strip().splitlines()
                assert len(lines) == 2


class TestForwardToS3:
    def test_skips_without_bucket(self):
        with patch("app.core.audit_log._S3_BUCKET", ""):
            forward_to_s3({"id": "test"})

    @patch("app.core.audit_log._s3")
    def test_forwards_when_configured(self, mock_s3_fn):
        mock_client = MagicMock()
        mock_s3_fn.return_value = mock_client
        with patch("app.core.audit_log._S3_BUCKET", "my-bucket"):
            forward_to_s3({"id": "ev1", "ts": "2024-01-01T00:00:00Z"})
            mock_client.put_object.assert_called_once()
            call_kwargs = mock_client.put_object.call_args[1]
            assert "ev1" in call_kwargs["Key"]

    @patch("app.core.audit_log._s3", return_value=None)
    def test_skips_when_no_client(self, mock_s3_fn):
        with patch("app.core.audit_log._S3_BUCKET", "my-bucket"):
            forward_to_s3({"id": "test"})


class TestPersist:
    def test_calls_append(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("app.core.audit_log._LOG_DIR", tmpdir), \
                 patch("app.core.audit_log._S3_BUCKET", ""):
                persist({"id": "ev_persist"})
                log_path = Path(tmpdir) / "timeline.jsonl"
                assert log_path.exists()
