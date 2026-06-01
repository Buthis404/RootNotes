"""Tests for app.core.ssh_exec — cancellable and streaming execution paths."""
import subprocess
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from app.core.ssh_exec import (
    run_ssh_command,
    run_ssh_command_cancellable,
    run_ssh_command_streaming,
    _communicate_with_timeout,
    _cancel_watcher_thread,
)


class TestRunSshCommandValidation:
    def test_raises_on_missing_host(self):
        with pytest.raises(ValueError, match="incomplete"):
            run_ssh_command({"username": "root"}, "ls", 10)

    def test_raises_on_missing_username(self):
        with pytest.raises(ValueError, match="incomplete"):
            run_ssh_command({"host": "10.0.0.1"}, "ls", 10)

    def test_raises_on_empty_command(self):
        with pytest.raises(ValueError, match="empty"):
            run_ssh_command({"host": "10.0.0.1", "username": "root"}, "  ", 10)


class TestRunSshCommandCancellable:
    def test_raises_on_missing_host(self):
        with pytest.raises(ValueError):
            run_ssh_command_cancellable({"username": "root"}, "ls", 10)

    def test_raises_on_empty_command(self):
        with pytest.raises(ValueError):
            run_ssh_command_cancellable({"host": "10.0.0.1", "username": "root"}, " ", 10)

    @patch("app.core.ssh_exec.subprocess.Popen")
    @patch("app.core.ssh_exec._prepare_ssh")
    def test_success_path(self, mock_prepare, mock_popen_cls):
        mock_prepare.return_value = (["ssh", "root@10.0.0.1", "ls"], {}, [])
        proc = MagicMock()
        proc.communicate.return_value = ("output", "")
        proc.returncode = 0
        mock_popen_cls.return_value = proc

        result = run_ssh_command_cancellable(
            {"host": "10.0.0.1", "username": "root"}, "ls", 10
        )
        assert result["ok"] is True
        assert result["cancelled"] is False

    @patch("app.core.ssh_exec.subprocess.Popen")
    @patch("app.core.ssh_exec._prepare_ssh")
    def test_cancelled(self, mock_prepare, mock_popen_cls):
        token = MagicMock()
        token.is_cancelled = True
        mock_prepare.return_value = (["ssh", "root@10.0.0.1", "ls"], {}, [])
        proc = MagicMock()
        proc.communicate.return_value = ("", "")
        proc.returncode = 0
        mock_popen_cls.return_value = proc

        result = run_ssh_command_cancellable(
            {"host": "10.0.0.1", "username": "root"}, "ls", 10, cancel_token=token
        )
        assert result["cancelled"] is True

    @patch("app.core.ssh_exec.subprocess.Popen")
    @patch("app.core.ssh_exec._prepare_ssh")
    def test_timeout(self, mock_prepare, mock_popen_cls):
        mock_prepare.return_value = (["ssh", "root@10.0.0.1", "ls"], {}, [])
        proc = MagicMock()
        proc.communicate.side_effect = [
            subprocess.TimeoutExpired("cmd", 10),
            ("", "err"),
        ]
        mock_popen_cls.return_value = proc

        result = run_ssh_command_cancellable(
            {"host": "10.0.0.1", "username": "root"}, "ls", 10
        )
        assert result["ok"] is False


class TestRunSshCommandStreaming:
    def test_raises_on_missing_host(self):
        with pytest.raises(ValueError):
            run_ssh_command_streaming({"username": "root"}, "ls", 10)

    def test_raises_on_empty_command(self):
        with pytest.raises(ValueError):
            run_ssh_command_streaming({"host": "10.0.0.1", "username": "root"}, " ", 10)

    @patch("app.core.ssh_exec.subprocess.Popen")
    @patch("app.core.ssh_exec._prepare_ssh")
    def test_streams_lines(self, mock_prepare, mock_popen_cls):
        mock_prepare.return_value = (["ssh", "root@10.0.0.1", "ls"], {}, [])
        proc = MagicMock()
        proc.stdout = iter(["line1\n", "line2\n"])
        proc.stderr = iter([])
        proc.returncode = 0
        proc.wait.return_value = 0
        mock_popen_cls.return_value = proc

        lines = []
        result = run_ssh_command_streaming(
            {"host": "10.0.0.1", "username": "root"}, "ls", 10,
            on_line=lines.append,
        )
        assert result["ok"] is True
        assert len(lines) == 2


class TestCommunicateWithTimeout:
    def test_success(self):
        proc = MagicMock()
        proc.communicate.return_value = ("out", "err")
        stdout, stderr, err_kind = _communicate_with_timeout(proc, 10)
        assert stdout == "out"
        assert stderr == "err"
        assert err_kind is None

    def test_timeout(self):
        proc = MagicMock()
        proc.communicate.side_effect = [
            subprocess.TimeoutExpired("cmd", 10),
            ("", "err"),
        ]
        stdout, stderr, err_kind = _communicate_with_timeout(proc, 10)
        assert err_kind == "timeout"
        proc.kill.assert_called()

    def test_exception(self):
        proc = MagicMock()
        proc.communicate.side_effect = OSError("broken pipe")
        stdout, stderr, err_kind = _communicate_with_timeout(proc, 10)
        assert err_kind == "exception"


class TestCancelWatcherThread:
    def test_kills_on_cancel(self):
        proc = MagicMock()
        token = MagicMock()
        token.is_cancelled = True
        evt = MagicMock()
        evt.wait.side_effect = [False, True]
        _cancel_watcher_thread(proc, token, evt)
        proc.kill.assert_called()

    def test_no_kill_when_not_cancelled(self):
        proc = MagicMock()
        token = MagicMock()
        token.is_cancelled = False
        evt = MagicMock()
        evt.wait.return_value = True
        _cancel_watcher_thread(proc, token, evt)
        proc.kill.assert_not_called()
