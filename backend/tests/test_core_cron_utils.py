"""Unit tests for app.core.cron_utils cron expression parser."""
from datetime import datetime

from app.core.cron_utils import cron_matches, next_run, validate_cron, _field_values


class TestFieldValues:
    def test_wildcard(self):
        assert _field_values("*", 0, 5) == {0, 1, 2, 3, 4, 5}

    def test_single_value(self):
        assert _field_values("5", 0, 59) == {5}

    def test_range(self):
        assert _field_values("1-5", 0, 59) == {1, 2, 3, 4, 5}

    def test_step_wildcard(self):
        assert _field_values("*/15", 0, 59) == {0, 15, 30, 45}

    def test_step_range(self):
        assert _field_values("10-20/5", 0, 59) == {10, 15, 20}

    def test_list(self):
        assert _field_values("1,3,5", 0, 59) == {1, 3, 5}

    def test_mixed_list(self):
        result = _field_values("1,3-5", 0, 59)
        assert result == {1, 3, 4, 5}

    def test_step_single_base(self):
        assert _field_values("0/10", 0, 59) == {0}


class TestCronMatches:
    def test_every_minute(self):
        assert cron_matches("* * * * *", datetime(2026, 1, 15, 10, 30))

    def test_specific_minute(self):
        assert cron_matches("30 * * * *", datetime(2026, 1, 15, 10, 30))
        assert not cron_matches("30 * * * *", datetime(2026, 1, 15, 10, 31))

    def test_specific_hour(self):
        assert cron_matches("* 10 * * *", datetime(2026, 1, 15, 10, 30))
        assert not cron_matches("* 10 * * *", datetime(2026, 1, 15, 11, 30))

    def test_specific_dom(self):
        assert cron_matches("* * 15 * *", datetime(2026, 1, 15, 10, 30))
        assert not cron_matches("* * 15 * *", datetime(2026, 1, 16, 10, 30))

    def test_specific_month(self):
        assert cron_matches("* * * 1 *", datetime(2026, 1, 15, 10, 30))
        assert not cron_matches("* * * 1 *", datetime(2026, 2, 15, 10, 30))

    def test_specific_dow(self):
        dt_thursday = datetime(2026, 1, 15)
        assert cron_matches("* * * * 4", dt_thursday)

    def test_sunday_dow_zero(self):
        dt_sunday = datetime(2026, 1, 11)
        assert cron_matches("* * * * 0", dt_sunday)

    def test_invalid_expression(self):
        assert not cron_matches("bad", datetime(2026, 1, 15, 10, 30))

    def test_too_few_fields(self):
        assert not cron_matches("* * *", datetime(2026, 1, 15, 10, 30))

    def test_step_minute(self):
        assert cron_matches("*/15 * * * *", datetime(2026, 1, 15, 10, 0))
        assert cron_matches("*/15 * * * *", datetime(2026, 1, 15, 10, 15))
        assert not cron_matches("*/15 * * * *", datetime(2026, 1, 15, 10, 7))


class TestNextRun:
    def test_every_minute(self):
        after = datetime(2026, 1, 15, 10, 30)
        result = next_run("* * * * *", after)
        assert result == datetime(2026, 1, 15, 10, 31)

    def test_specific_minute(self):
        after = datetime(2026, 1, 15, 10, 0)
        result = next_run("30 * * * *", after)
        assert result == datetime(2026, 1, 15, 10, 30)

    def test_next_hour(self):
        after = datetime(2026, 1, 15, 10, 31)
        result = next_run("0 * * * *", after)
        assert result == datetime(2026, 1, 15, 11, 0)

    def test_hourly_at_30(self):
        after = datetime(2026, 1, 15, 10, 31)
        result = next_run("30 * * * *", after)
        assert result == datetime(2026, 1, 15, 11, 30)

    def test_daily_midnight(self):
        after = datetime(2026, 1, 15, 10, 0)
        result = next_run("0 0 * * *", after)
        assert result == datetime(2026, 1, 16, 0, 0)

    def test_with_none_after(self):
        result = next_run("* * * * *")
        assert isinstance(result, datetime)


class TestValidateCron:
    def test_valid_every_minute(self):
        assert validate_cron("* * * * *")

    def test_valid_specific(self):
        assert validate_cron("30 10 * * 1")

    def test_valid_step(self):
        assert validate_cron("*/15 * * * *")

    def test_too_few_fields(self):
        assert not validate_cron("* * *")

    def test_too_many_fields(self):
        assert not validate_cron("* * * * * *")

    def test_invalid_field(self):
        assert not validate_cron("abc * * * *")

    def test_empty(self):
        assert not validate_cron("")

    def test_non_numeric_field(self):
        assert not validate_cron("abc * * * *")
