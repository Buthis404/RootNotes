"""Unit tests for app.core.enums — enum lookups and helpers."""
from app.core.enums import (
    FindingStatus,
    HostStatus,
    JobStatus,
    MemberRole,
    Severity,
    UserRole,
    _StrEnumBase,
)


class TestStrEnumBaseValues:
    def test_user_role(self):
        vals = UserRole.values()
        assert "admin" in vals
        assert "user" in vals
        assert "viewer" in vals

    def test_member_role(self):
        vals = MemberRole.values()
        assert "owner" in vals
        assert "editor" in vals
        assert "viewer" in vals
        assert "auditor" in vals

    def test_severity(self):
        vals = Severity.values()
        assert "critical" in vals
        assert "high" in vals
        assert "medium" in vals
        assert "low" in vals
        assert "info" in vals

    def test_host_status(self):
        vals = HostStatus.values()
        assert "unknown" in vals
        assert "up" in vals
        assert "down" in vals
        assert "pwned" in vals

    def test_finding_status(self):
        vals = FindingStatus.values()
        assert "open" in vals
        assert "resolved" in vals
        assert "closed" in vals
        assert "false_positive" in vals

    def test_job_status(self):
        vals = JobStatus.values()
        assert "queued" in vals
        assert "running" in vals
        assert "done" in vals
        assert "failed" in vals


class TestStrEnumBaseCoerce:
    def test_valid_string(self):
        assert UserRole.coerce("admin") == UserRole.ADMIN

    def test_case_insensitive(self):
        assert UserRole.coerce("ADMIN") == UserRole.ADMIN
        assert UserRole.coerce("Admin") == UserRole.ADMIN

    def test_whitespace(self):
        assert UserRole.coerce("  admin  ") == UserRole.ADMIN

    def test_enum_passthrough(self):
        assert UserRole.coerce(UserRole.ADMIN) == UserRole.ADMIN

    def test_none_returns_none(self):
        assert UserRole.coerce(None) is None

    def test_invalid_returns_none(self):
        assert UserRole.coerce("nonexistent") is None

    def test_empty_string_returns_none(self):
        assert UserRole.coerce("") is None

    def test_severity_coerce(self):
        assert Severity.coerce("critical") == Severity.CRITICAL
        assert Severity.coerce("HIGH") == Severity.HIGH

    def test_host_status_coerce(self):
        assert HostStatus.coerce("pwned") == HostStatus.PWNED

    def test_finding_status_coerce(self):
        assert FindingStatus.coerce("false_positive") == FindingStatus.FALSE_POSITIVE

    def test_member_role_coerce(self):
        assert MemberRole.coerce("owner") == MemberRole.OWNER

    def test_job_status_coerce(self):
        assert JobStatus.coerce("cancelled") == JobStatus.CANCELLED


class TestJobStatusTerminal:
    def test_terminal_states(self):
        terminal = JobStatus.terminal()
        assert "done" in terminal
        assert "failed" in terminal
        assert "cancelled" in terminal
        assert "skipped" in terminal

    def test_non_terminal_states(self):
        terminal = JobStatus.terminal()
        assert "queued" not in terminal
        assert "running" not in terminal


class TestEnumStrComparison:
    def test_str_comparison(self):
        assert UserRole.ADMIN == "admin"
        assert Severity.CRITICAL == "critical"

    def test_in_set(self):
        s = {"admin", "user"}
        assert UserRole.ADMIN in s

    def test_member_count(self):
        assert len(UserRole.values()) == 3
        assert len(MemberRole.values()) == 6
        assert len(Severity.values()) == 5
        assert len(JobStatus.values()) == 6
