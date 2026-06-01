import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
import os

from app.core.plugin_signing import (
    signing_enabled,
    require_signature,
    sign_content,
    verify_signature,
)


class TestSigningEnabled:
    def test_with_key(self, monkeypatch):
        monkeypatch.setenv("PLUGIN_SIGNING_KEY", "testkey123")
        import importlib
        import app.core.plugin_signing as mod
        importlib.reload(mod)
        assert mod.signing_enabled() is True

    def test_without_key(self, monkeypatch):
        monkeypatch.delenv("PLUGIN_SIGNING_KEY", raising=False)
        import importlib
        import app.core.plugin_signing as mod
        importlib.reload(mod)
        assert mod.signing_enabled() is False


class TestRequireSignature:
    def test_required_and_enabled(self, monkeypatch):
        monkeypatch.setenv("PLUGIN_SIGNING_KEY", "testkey123")
        monkeypatch.setenv("PLUGIN_REQUIRE_SIGNATURE", "true")
        import importlib
        import app.core.plugin_signing as mod
        importlib.reload(mod)
        assert mod.require_signature() is True

    def test_required_but_disabled(self, monkeypatch):
        monkeypatch.delenv("PLUGIN_SIGNING_KEY", raising=False)
        monkeypatch.setenv("PLUGIN_REQUIRE_SIGNATURE", "true")
        import importlib
        import app.core.plugin_signing as mod
        importlib.reload(mod)
        assert mod.require_signature() is False

    def test_not_required(self, monkeypatch):
        monkeypatch.setenv("PLUGIN_SIGNING_KEY", "testkey123")
        monkeypatch.setenv("PLUGIN_REQUIRE_SIGNATURE", "false")
        import importlib
        import app.core.plugin_signing as mod
        importlib.reload(mod)
        assert mod.require_signature() is False


class TestSignContent:
    def test_sign_bytes(self, monkeypatch):
        monkeypatch.setenv("PLUGIN_SIGNING_KEY", "secretkey")
        import importlib
        import app.core.plugin_signing as mod
        importlib.reload(mod)
        result = mod.sign_content(b"hello world")
        assert result.startswith("sha256=")

    def test_sign_string(self, monkeypatch):
        monkeypatch.setenv("PLUGIN_SIGNING_KEY", "secretkey")
        import importlib
        import app.core.plugin_signing as mod
        importlib.reload(mod)
        result = mod.sign_content("hello world")
        assert result.startswith("sha256=")

    def test_no_key_raises(self, monkeypatch):
        monkeypatch.delenv("PLUGIN_SIGNING_KEY", raising=False)
        import importlib
        import app.core.plugin_signing as mod
        importlib.reload(mod)
        with pytest.raises(ValueError):
            mod.sign_content("test")


class TestVerifySignature:
    def test_valid(self, monkeypatch):
        monkeypatch.setenv("PLUGIN_SIGNING_KEY", "secretkey")
        import importlib
        import app.core.plugin_signing as mod
        importlib.reload(mod)
        sig = mod.sign_content("hello")
        assert mod.verify_signature("hello", sig) is True

    def test_invalid(self, monkeypatch):
        monkeypatch.setenv("PLUGIN_SIGNING_KEY", "secretkey")
        import importlib
        import app.core.plugin_signing as mod
        importlib.reload(mod)
        assert mod.verify_signature("hello", "sha256=bad") is False

    def test_no_key(self, monkeypatch):
        monkeypatch.delenv("PLUGIN_SIGNING_KEY", raising=False)
        import importlib
        import app.core.plugin_signing as mod
        importlib.reload(mod)
        assert mod.verify_signature("hello", "sha256=abc") is False
