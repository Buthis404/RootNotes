"""Tests for app.core.job_streams — in-memory stream buffer management."""

import time
from app.core import job_streams


class TestInitStream:
    def test_creates_buffer(self):
        job_streams._buffers.clear()
        job_streams.init_stream("j1")
        assert "j1" in job_streams._buffers
        assert job_streams._buffers["j1"]["lines"] == []
        assert job_streams._buffers["j1"]["closed"] is False

    def test_reinit_resets_buffer(self):
        job_streams._buffers.clear()
        job_streams.init_stream("j1")
        job_streams.push_line("j1", "line1")
        job_streams.init_stream("j1")
        assert job_streams.get_lines("j1") == []


class TestPushLine:
    def test_appends_line(self):
        job_streams._buffers.clear()
        job_streams.init_stream("j1")
        job_streams.push_line("j1", "hello")
        job_streams.push_line("j1", "world")
        assert job_streams.get_lines("j1") == ["hello", "world"]

    def test_ignores_unknown_job(self):
        job_streams._buffers.clear()
        job_streams.push_line("nonexistent", "line")

    def test_ignores_closed_stream(self):
        job_streams._buffers.clear()
        job_streams.init_stream("j1")
        job_streams.close_stream("j1")
        job_streams.push_line("j1", "should not appear")
        assert job_streams.get_lines("j1") == []


class TestGetLines:
    def test_from_idx(self):
        job_streams._buffers.clear()
        job_streams.init_stream("j1")
        job_streams.push_line("j1", "a")
        job_streams.push_line("j1", "b")
        job_streams.push_line("j1", "c")
        assert job_streams.get_lines("j1", 1) == ["b", "c"]

    def test_unknown_job_returns_empty(self):
        job_streams._buffers.clear()
        assert job_streams.get_lines("nope") == []

    def test_out_of_range_idx(self):
        job_streams._buffers.clear()
        job_streams.init_stream("j1")
        job_streams.push_line("j1", "a")
        assert job_streams.get_lines("j1", 5) == []


class TestIsClosed:
    def test_open(self):
        job_streams._buffers.clear()
        job_streams.init_stream("j1")
        assert job_streams.is_closed("j1") is False

    def test_closed(self):
        job_streams._buffers.clear()
        job_streams.init_stream("j1")
        job_streams.close_stream("j1")
        assert job_streams.is_closed("j1") is True

    def test_unknown_is_closed(self):
        job_streams._buffers.clear()
        assert job_streams.is_closed("nope") is True


class TestCloseStream:
    def test_sets_closed_and_timestamp(self):
        job_streams._buffers.clear()
        job_streams.init_stream("j1")
        job_streams.close_stream("j1")
        assert job_streams._buffers["j1"]["closed"] is True
        assert job_streams._buffers["j1"]["closed_at"] is not None

    def test_unknown_job_no_error(self):
        job_streams._buffers.clear()
        job_streams.close_stream("nope")


class TestCleanupExpired:
    def test_removes_old_closed(self):
        job_streams._buffers.clear()
        job_streams.init_stream("j1")
        job_streams.close_stream("j1")
        job_streams._buffers["j1"]["closed_at"] = time.monotonic() - 600
        job_streams.cleanup_expired()
        assert "j1" not in job_streams._buffers

    def test_keeps_recent_closed(self):
        job_streams._buffers.clear()
        job_streams.init_stream("j1")
        job_streams.close_stream("j1")
        job_streams.cleanup_expired()
        assert "j1" in job_streams._buffers

    def test_keeps_open_buffers(self):
        job_streams._buffers.clear()
        job_streams.init_stream("j1")
        job_streams._buffers["j1"]["closed_at"] = time.monotonic() - 600
        job_streams.cleanup_expired()
        assert "j1" in job_streams._buffers
