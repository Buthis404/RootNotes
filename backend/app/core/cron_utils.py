"""
Minimal cron expression parser (no external deps).
Supports: * */n n-m a,b,c  for each of the 5 fields.
Day-of-week: 0=Sun … 6=Sat (standard cron).
"""
from datetime import datetime, timedelta
from typing import Optional


def _field_values(field: str, lo: int, hi: int) -> set:
    """Expand a cron field to the set of matching integer values."""
    result = set()
    for part in field.split(","):
        if part == "*":
            result.update(range(lo, hi + 1))
        elif "/" in part:
            base, step = part.split("/", 1)
            step = int(step)
            if base == "*":
                start = lo
                end = hi
            elif "-" in base:
                a, b = base.split("-")
                start, end = int(a), int(b)
            else:
                start = end = int(base)
            result.update(range(start, end + 1, step))
        elif "-" in part:
            a, b = part.split("-", 1)
            result.update(range(int(a), int(b) + 1))
        else:
            result.add(int(part))
    return result


def cron_matches(expr: str, dt: datetime) -> bool:
    """Return True if *dt* matches the 5-field cron expression."""
    parts = expr.strip().split()
    if len(parts) != 5:
        return False
    minute_f, hour_f, dom_f, month_f, dow_f = parts
    # Python weekday: Mon=0..Sun=6 → cron: Sun=0..Sat=6
    cron_dow = (dt.weekday() + 1) % 7
    return (
        dt.minute in _field_values(minute_f, 0, 59)
        and dt.hour in _field_values(hour_f, 0, 23)
        and dt.day in _field_values(dom_f, 1, 31)
        and dt.month in _field_values(month_f, 1, 12)
        and cron_dow in _field_values(dow_f, 0, 6)
    )


def next_run(expr: str, after: Optional[datetime] = None) -> datetime:
    """Return the next datetime (minute granularity) that matches *expr*."""
    dt = (after or utcnow()).replace(second=0, microsecond=0) + timedelta(minutes=1)
    for _ in range(527041):  # max one year of minutes
        if cron_matches(expr, dt):
            return dt
        dt += timedelta(minutes=1)
    raise ValueError(f"No match found for cron expression: {expr!r}")


def validate_cron(expr: str) -> bool:
    try:
        parts = expr.strip().split()
        if len(parts) != 5:
            return False
        limits = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 6)]
        for field, (lo, hi) in zip(parts, limits):
            _field_values(field, lo, hi)
        return True
    except Exception:
        return False
