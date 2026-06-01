"""Tests for app.core.security — password hashing, JWT token creation."""

import pytest
from unittest.mock import MagicMock

from app.core.security import (
    gen_password,
    hash_password,
    verify_password,
    make_token,
    decode_token,
)


class TestGenPassword:
    def test_default_length(self):
        p = gen_password()
        assert len(p) == 12

    def test_custom_length(self):
        p = gen_password(20)
        assert len(p) == 20

    def test_alphanumeric(self):
        p = gen_password(100)
        assert p.isalnum()

    def test_unique(self):
        assert gen_password() != gen_password()


class TestHashPassword:
    def test_hashes_differently(self):
        h1 = hash_password("same")
        h2 = hash_password("same")
        assert h1 != h2

    def test_hash_is_string(self):
        h = hash_password("test")
        assert isinstance(h, str)

    def test_empty_password(self):
        h = hash_password("")
        assert isinstance(h, str)


class TestVerifyPassword:
    def test_correct_password(self):
        h = hash_password("secret")
        assert verify_password("secret", h) is True

    def test_wrong_password(self):
        h = hash_password("secret")
        assert verify_password("wrong", h) is False

    def test_empty_password_against_hash(self):
        h = hash_password("")
        assert verify_password("", h) is True


class TestMakeAndDecodeToken:
    def test_roundtrip(self):
        user = MagicMock()
        user.id = "usr12345"
        user.username = "admin"
        user.role = "admin"
        token = make_token(user)
        decoded = decode_token(token)
        assert decoded is not None
        assert decoded["sub"] == "usr12345"
        assert decoded["username"] == "admin"
        assert decoded["role"] == "admin"
        assert "exp" in decoded
        assert "jti" in decoded

    def test_invalid_token_returns_none(self):
        assert decode_token("invalid.token.here") is None

    def test_empty_token_returns_none(self):
        assert decode_token("") is None

    def test_token_has_jti(self):
        user = MagicMock()
        user.id = "u1"
        user.username = "test"
        user.role = "user"
        token = make_token(user)
        decoded = decode_token(token)
        assert len(decoded["jti"]) == 32

    def test_different_users_different_tokens(self):
        u1 = MagicMock(id="u1", username="a", role="user")
        u2 = MagicMock(id="u2", username="b", role="admin")
        assert make_token(u1) != make_token(u2)
