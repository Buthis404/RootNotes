import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
import os
import tempfile

from app.core.crypto import (
    encrypt_str,
    decrypt_str,
    is_encrypted,
    encrypt_bytes,
    decrypt_bytes,
    note_content_is_confidential,
    loot_value_is_sensitive,
    validate_encryption_config,
)


class TestEncryptDecryptStr:
    def test_roundtrip(self):
        encrypted = encrypt_str("secret")
        assert encrypted.startswith("__enc__:")
        assert decrypt_str(encrypted) == "secret"

    def test_empty(self):
        assert encrypt_str("") == ""

    def test_no_double_encrypt(self):
        encrypted = encrypt_str("secret")
        encrypted2 = encrypt_str(encrypted)
        assert encrypted == encrypted2

    def test_decrypt_non_encrypted(self):
        assert decrypt_str("plain") == "plain"

    def test_decrypt_empty(self):
        assert decrypt_str("") == ""

    def test_is_encrypted(self):
        encrypted = encrypt_str("secret")
        assert is_encrypted(encrypted) is True
        assert is_encrypted("plain") is False
        assert is_encrypted("") is False


class TestEncryptDecryptBytes:
    def test_roundtrip(self):
        encrypted = encrypt_bytes(b"binary data")
        assert isinstance(encrypted, bytes)
        assert decrypt_bytes(encrypted) == b"binary data"


class TestNoteContentIsConfidential:
    def test_confidential(self):
        assert note_content_is_confidential(["confidential"]) is True

    def test_secret(self):
        assert note_content_is_confidential(["secret"]) is True

    def test_normal(self):
        assert note_content_is_confidential(["normal"]) is False

    def test_none(self):
        assert note_content_is_confidential(None) is False

    def test_empty(self):
        assert note_content_is_confidential([]) is False


class TestLootValueIsSensitive:
    def test_has_storage_path(self):
        assert loot_value_is_sensitive(storage_path="/tmp/x") is False

    def test_has_public_url(self):
        assert loot_value_is_sensitive(public_url="http://x") is False

    def test_has_filename(self):
        assert loot_value_is_sensitive(filename="x.txt") is False

    def test_file_artifact(self):
        assert loot_value_is_sensitive(artifact_type="file") is False

    def test_file_loot_type(self):
        assert loot_value_is_sensitive(loot_type="file") is False

    def test_sensitive(self):
        assert loot_value_is_sensitive(loot_type="hash", artifact_type="password") is True


class TestValidateEncryptionConfig:
    def test_dev_mode(self, monkeypatch):
        monkeypatch.setenv("APP_ENV", "dev")
        validate_encryption_config()

    def test_test_mode(self, monkeypatch):
        monkeypatch.setenv("APP_ENV", "test")
        validate_encryption_config()

    def test_prod_with_key(self, monkeypatch):
        monkeypatch.setenv("APP_ENV", "production")
        monkeypatch.setenv("ENCRYPTION_KEY", "validkey123")
        import importlib
        import app.core.crypto as mod
        mod._fernet_instance = None
        from cryptography.fernet import Fernet
        monkeypatch.setenv("ENCRYPTION_KEY", Fernet.generate_key().decode())
        validate_encryption_config()

    def test_prod_no_key_raises(self, monkeypatch):
        monkeypatch.setenv("APP_ENV", "production")
        monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
        with pytest.raises(RuntimeError, match="ENCRYPTION_KEY"):
            validate_encryption_config()
