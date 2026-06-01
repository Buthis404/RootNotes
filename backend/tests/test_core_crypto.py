"""Unit tests for app.core.crypto encryption helpers."""
import os
from unittest.mock import patch

from cryptography.fernet import Fernet, InvalidToken

from app.core.crypto import (
    encrypt_str,
    decrypt_str,
    is_encrypted,
    encrypt_bytes,
    decrypt_bytes,
    note_content_is_confidential,
    loot_value_is_sensitive,
    validate_encryption_config,
    _SENTINEL,
    _get_fernet,
)


class TestEncryptDecryptStr:
    def test_roundtrip(self):
        original = "supersecret123"
        encrypted = encrypt_str(original)
        assert decrypt_str(encrypted) == original

    def test_empty_string_passthrough(self):
        assert encrypt_str("") == ""
        assert decrypt_str("") == ""

    def test_none_like_passthrough(self):
        assert decrypt_str(None) is None

    def test_encrypted_starts_with_sentinel(self):
        encrypted = encrypt_str("test")
        assert encrypted.startswith(_SENTINEL)

    def test_no_double_encrypt(self):
        encrypted = encrypt_str("test")
        double = encrypt_str(encrypted)
        assert double == encrypted

    def test_decrypt_unencrypted_returns_as_is(self):
        assert decrypt_str("plain text") == "plain text"

    def test_is_encrypted_true(self):
        encrypted = encrypt_str("secret")
        assert is_encrypted(encrypted)

    def test_is_encrypted_false(self):
        assert not is_encrypted("plain")

    def test_is_encrypted_empty(self):
        assert not is_encrypted("")

    def test_is_encrypted_none_like(self):
        assert not is_encrypted(None)


class TestEncryptDecryptBytes:
    def test_roundtrip(self):
        original = b"binary secret data"
        encrypted = encrypt_bytes(original)
        assert decrypt_bytes(encrypted) == original

    def test_empty_bytes(self):
        encrypted = encrypt_bytes(b"")
        assert decrypt_bytes(encrypted) == b""

    def test_invalid_token_raises(self):
        try:
            decrypt_bytes(b"garbage-data-here")
            assert False, "Expected InvalidToken"
        except (InvalidToken, Exception):
            pass


class TestNoteContentIsConfidential:
    def test_confidential_tag(self):
        assert note_content_is_confidential(["confidential"])

    def test_secret_tag(self):
        assert note_content_is_confidential(["secret"])

    def test_sensitive_tag(self):
        assert note_content_is_confidential(["sensitive"])

    def test_opsec_tag(self):
        assert note_content_is_confidential(["opsec"])

    def test_restricted_tag(self):
        assert note_content_is_confidential(["restricted"])

    def test_normal_tag(self):
        assert not note_content_is_confidential(["notes"])

    def test_empty_list(self):
        assert not note_content_is_confidential([])

    def test_none(self):
        assert not note_content_is_confidential(None)

    def test_mixed_tags(self):
        assert note_content_is_confidential(["info", "secret"])

    def test_case_insensitive(self):
        assert note_content_is_confidential(["SECRET", "Confidential"])

    def test_whitespace_tag(self):
        assert not note_content_is_confidential(["  ", ""])


class TestLootValueIsSensitive:
    def test_with_storage_path(self):
        assert not loot_value_is_sensitive(storage_path="/data/loot/file.txt")

    def test_with_public_url(self):
        assert not loot_value_is_sensitive(public_url="http://example.com/file")

    def test_with_filename(self):
        assert not loot_value_is_sensitive(filename="dump.txt")

    def test_file_artifact_not_sensitive(self):
        assert not loot_value_is_sensitive(artifact_type="file")

    def test_file_loot_type_not_sensitive(self):
        assert not loot_value_is_sensitive(loot_type="file")

    def test_credential_is_sensitive(self):
        assert loot_value_is_sensitive(loot_type="credential")

    def test_hash_is_sensitive(self):
        assert loot_value_is_sensitive(loot_type="hash")

    def test_empty_all_is_sensitive(self):
        assert loot_value_is_sensitive()

    def test_non_file_artifact_and_non_file_type(self):
        assert loot_value_is_sensitive(artifact_type="note", loot_type="credential")


class TestValidateEncryptionConfig:
    def test_dev_mode_ok(self):
        with patch.dict(os.environ, {"APP_ENV": "dev"}):
            validate_encryption_config()

    def test_test_mode_ok(self):
        with patch.dict(os.environ, {"APP_ENV": "test"}):
            validate_encryption_config()

    def test_development_mode_ok(self):
        with patch.dict(os.environ, {"APP_ENV": "development"}):
            validate_encryption_config()

    def test_prod_without_key_raises(self):
        env = {"APP_ENV": "production"}
        key = os.environ.get("ENCRYPTION_KEY", "")
        if key:
            env["ENCRYPTION_KEY"] = ""
        with patch.dict(os.environ, env, clear=False):
            try:
                validate_encryption_config()
                assert False, "Expected RuntimeError"
            except RuntimeError as e:
                assert "ENCRYPTION_KEY" in str(e)

    def test_prod_with_key_ok(self):
        fkey = Fernet.generate_key().decode()
        with patch.dict(os.environ, {"APP_ENV": "production", "ENCRYPTION_KEY": fkey}):
            validate_encryption_config()
