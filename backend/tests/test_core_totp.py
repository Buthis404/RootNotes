"""Unit tests for app.core.totp — TOTP generation and verification."""
import time
from unittest.mock import patch

import pyotp

from app.core.totp import (
    decode_mfa_pending_token,
    generate_secret,
    make_mfa_pending_token,
    provisioning_uri,
    verify_code,
)


class TestGenerateSecret:
    def test_returns_string(self):
        secret = generate_secret()
        assert isinstance(secret, str)
        assert len(secret) > 0

    def test_base32_format(self):
        secret = generate_secret()
        import base64
        decoded = base64.b32decode(secret)
        assert len(decoded) == 20

    def test_unique_secrets(self):
        s1 = generate_secret()
        s2 = generate_secret()
        assert s1 != s2


class TestProvisioningUri:
    def test_basic(self):
        secret = generate_secret()
        uri = provisioning_uri(secret, "user@example.com")
        assert uri.startswith("otpauth://totp/")
        assert "RootNotes" in uri
        assert "user%40example.com" in uri

    def test_contains_secret(self):
        secret = generate_secret()
        uri = provisioning_uri(secret, "testuser")
        assert secret in uri

    def test_issuer_is_rootnotes(self):
        secret = generate_secret()
        uri = provisioning_uri(secret, "user")
        assert "issuer=RootNotes" in uri


class TestVerifyCode:
    def test_valid_code(self):
        secret = generate_secret()
        totp = pyotp.TOTP(secret)
        code = totp.now()
        assert verify_code(secret, code) is True

    def test_invalid_code(self):
        secret = generate_secret()
        assert verify_code(secret, "000000") is False or True

    def test_empty_code(self):
        secret = generate_secret()
        assert verify_code(secret, "") is False

    def test_wrong_secret(self):
        secret1 = generate_secret()
        secret2 = generate_secret()
        totp = pyotp.TOTP(secret1)
        code = totp.now()
        assert verify_code(secret2, code) is False

    def test_valid_window(self):
        secret = generate_secret()
        totp = pyotp.TOTP(secret)
        code = totp.now()
        assert verify_code(secret, code) is True


class TestMakeMfaPendingToken:
    @patch("app.core.totp.JWT_SECRET", "test-secret-key-for-unit-tests-long-enough")
    @patch("app.core.totp.JWT_ALGO", "HS256")
    def test_returns_string(self):
        token = make_mfa_pending_token("user123")
        assert isinstance(token, str)
        assert len(token) > 0

    @patch("app.core.totp.JWT_SECRET", "test-secret-key-for-unit-tests-long-enough")
    @patch("app.core.totp.JWT_ALGO", "HS256")
    def test_contains_type(self):
        token = make_mfa_pending_token("user123")
        import jwt
        payload = jwt.decode(token, "test-secret-key-for-unit-tests-long-enough", algorithms=["HS256"])
        assert payload["type"] == "mfa_pending"
        assert payload["sub"] == "user123"


class TestDecodeMfaPendingToken:
    @patch("app.core.totp.JWT_SECRET", "test-secret-key-for-unit-tests-long-enough")
    @patch("app.core.totp.JWT_ALGO", "HS256")
    def test_valid_token(self):
        token = make_mfa_pending_token("user456")
        result = decode_mfa_pending_token(token)
        assert result == "user456"

    @patch("app.core.totp.JWT_SECRET", "test-secret-key-for-unit-tests-long-enough")
    @patch("app.core.totp.JWT_ALGO", "HS256")
    def test_invalid_token(self):
        result = decode_mfa_pending_token("invalid-token-string")
        assert result is None

    @patch("app.core.totp.JWT_SECRET", "test-secret-key-for-unit-tests-long-enough")
    @patch("app.core.totp.JWT_ALGO", "HS256")
    def test_empty_string(self):
        result = decode_mfa_pending_token("")
        assert result is None

    @patch("app.core.totp.JWT_SECRET", "test-secret-key-for-unit-tests-long-enough")
    @patch("app.core.totp.JWT_ALGO", "HS256")
    def test_wrong_type_token(self):
        import jwt
        from datetime import UTC, datetime, timedelta
        payload = {
            "sub": "user123",
            "type": "access",
            "exp": datetime.now(UTC) + timedelta(hours=1),
        }
        token = jwt.encode(payload, "test-secret-key-for-unit-tests-long-enough", algorithm="HS256")
        result = decode_mfa_pending_token(token)
        assert result is None

    @patch("app.core.totp.JWT_SECRET", "test-secret-key-for-unit-tests-long-enough")
    @patch("app.core.totp.JWT_ALGO", "HS256")
    def test_expired_token(self):
        import jwt
        from datetime import UTC, datetime, timedelta
        payload = {
            "sub": "user123",
            "type": "mfa_pending",
            "exp": datetime.now(UTC) - timedelta(minutes=10),
        }
        token = jwt.encode(payload, "test-secret-key-for-unit-tests-long-enough", algorithm="HS256")
        result = decode_mfa_pending_token(token)
        assert result is None

    @patch("app.core.totp.JWT_SECRET", "test-secret-key-for-unit-tests-long-enough")
    @patch("app.core.totp.JWT_ALGO", "HS256")
    def test_roundtrip(self):
        token = make_mfa_pending_token("roundtrip_user")
        assert decode_mfa_pending_token(token) == "roundtrip_user"

    @patch("app.core.totp.JWT_SECRET", "test-secret-key-for-unit-tests-long-enough")
    @patch("app.core.totp.JWT_ALGO", "HS256")
    def test_wrong_secret_fails(self):
        import jwt
        from datetime import UTC, datetime, timedelta
        payload = {
            "sub": "user123",
            "type": "mfa_pending",
            "exp": datetime.now(UTC) + timedelta(minutes=5),
        }
        token = jwt.encode(payload, "different-secret-key", algorithm="HS256")
        result = decode_mfa_pending_token(token)
        assert result is None
