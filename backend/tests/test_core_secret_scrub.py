"""Unit tests for app.core.secret_scrub secret redaction."""
from app.core.secret_scrub import scrub_secret, scrub_secrets, scrub_for_cred, REDACTED


class TestScrubSecret:
    def test_basic_replacement(self):
        assert scrub_secret("pass=Secret123", "Secret123") == f"pass={REDACTED}"

    def test_multiple_occurrences(self):
        text = "user:admin pass:Secret123 confirm:Secret123"
        result = scrub_secret(text, "Secret123")
        assert result.count(REDACTED) == 2

    def test_none_secret(self):
        assert scrub_secret("text", None) == "text"

    def test_empty_secret(self):
        assert scrub_secret("text", "") == "text"

    def test_none_text(self):
        assert scrub_secret(None, "secret") is None

    def test_empty_text(self):
        assert scrub_secret("", "secret") == ""

    def test_short_secret_no_scrub(self):
        assert scrub_secret("abc", "ab") == "abc"

    def test_exactly_4_chars_scrubbed(self):
        assert REDACTED in scrub_secret("abcd secret", "abcd")

    def test_3_chars_no_scrub(self):
        result = scrub_secret("abc secret", "abc")
        assert result == "abc secret"


class TestScrubSecrets:
    def test_multiple_secrets(self):
        result = scrub_secrets("pass=abc123 key=xyz789", "abc123", "xyz789")
        assert "abc123" not in result
        assert "xyz789" not in result
        assert result.count(REDACTED) == 2

    def test_longest_first(self):
        result = scrub_secrets("value=abcde12345 value=abcde", "abcde", "abcde12345")
        assert "abcde12345" not in result
        assert "abcde" not in result

    def test_none_secrets(self):
        assert scrub_secrets("text", None, None) == "text"

    def test_empty_text(self):
        assert scrub_secrets("", "secret") == ""

    def test_none_text(self):
        assert scrub_secrets(None, "secret") is None

    def test_short_secrets_skipped(self):
        assert scrub_secrets("abc and secret", "ab", "secret") == f"abc and {REDACTED}"

    def test_no_secrets(self):
        assert scrub_secrets("hello world") == "hello world"


class TestScrubForCred:
    def test_basic(self):
        cred = {"secret": "Password123"}
        result = scrub_for_cred("pass=Password123", cred)
        assert REDACTED in result

    def test_none_cred(self):
        assert scrub_for_cred("text", None) == "text"

    def test_empty_cred(self):
        assert scrub_for_cred("text", {}) == "text"

    def test_no_secret_key(self):
        assert scrub_for_cred("text", {"user": "admin"}) == "text"
