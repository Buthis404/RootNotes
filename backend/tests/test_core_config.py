"""Tests for app.core.config — configuration loading logic."""

import os
import pytest
from pathlib import Path
from unittest.mock import patch, mock_open

from app.core.config import (
    _WEAK_SECRETS,
    _try_load_stored_secret,
    _load_jwt_secret,
    JWT_ALGO,
    COOKIE_NAME,
    SAFE_UPLOAD_RE,
)


class TestWeakSecrets:
    def test_empty_is_weak(self):
        assert "" in _WEAK_SECRETS

    def test_default_secrets_are_weak(self):
        assert "change-me-in-production" in _WEAK_SECRETS
        assert "redteam-notes-change-me-in-production" in _WEAK_SECRETS

    def test_strong_secret_not_weak(self):
        assert "a-very-long-and-secure-secret-key-12345" not in _WEAK_SECRETS


class TestTryLoadStoredSecret:
    def test_returns_none_when_file_missing(self):
        with patch.object(Path, "exists", return_value=False):
            result = _try_load_stored_secret("")
            assert result is None

    def test_returns_stored_when_raw_weak(self):
        with patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "read_text", return_value="stored-secret-that-is-long-enough"):
            result = _try_load_stored_secret("")
            assert result == "stored-secret-that-is-long-enough"

    def test_returns_none_when_raw_is_strong(self):
        with patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "read_text", return_value="stored-secret"):
            result = _try_load_stored_secret("a-strong-env-secret-value")
            assert result is None

    def test_handles_read_error(self):
        with patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "read_text", side_effect=OSError("nope")):
            result = _try_load_stored_secret("")
            assert result is None

    def test_returns_none_for_empty_stored(self):
        with patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "read_text", return_value=""):
            result = _try_load_stored_secret("")
            assert result is None


class TestLoadJwtSecret:
    def test_strong_env_used_directly(self):
        with patch.dict(os.environ, {"JWT_SECRET": "a-very-strong-secret-with-16-chars-min"}):
            result = _load_jwt_secret()
            assert result == "a-very-strong-secret-with-16-chars-min"

    def test_weak_env_generates(self):
        with patch.dict(os.environ, {"JWT_SECRET": "change-me-in-production"}), \
             patch("app.core.config._try_load_stored_secret", return_value=None), \
             patch("pathlib.Path.mkdir"), \
             patch("pathlib.Path.write_text"):
            result = _load_jwt_secret()
            assert len(result) == 64
            assert result != "change-me-in-production"

    def test_short_env_warns_but_uses(self):
        with patch.dict(os.environ, {"JWT_SECRET": "short"}):
            result = _load_jwt_secret()
            assert result == "short"


class TestConfigConstants:
    def test_jwt_algo(self):
        assert JWT_ALGO == "HS256"

    def test_cookie_name(self):
        assert COOKIE_NAME == "rt_auth"

    def test_safe_upload_re_rejects_special_chars(self):
        assert SAFE_UPLOAD_RE.search("../../etc/passwd") is not None

    def test_safe_upload_re_allows_safe_names(self):
        assert SAFE_UPLOAD_RE.search("file.txt") is None
        assert SAFE_UPLOAD_RE.search("report-2024.pdf") is None
