"""Consolidated tests for test_core_ssh_exec (merged variant files)."""

# ════════ from test_core_ssh_exec.py ════════
import pytest

from app.core.ssh_exec import (
    _known_hosts_mode,
    _base_ssh_cmd,
    _prepare_ssh,
    is_transport_failure,
    _TRANSPORT_ERROR_STRINGS,
)


class TestKnownHostsMode:
    def test_accept_new(self):
        assert _known_hosts_mode({"known_hosts_policy": "accept_new"}) == "accept-new"

    def test_default_is_yes(self):
        assert _known_hosts_mode({}) == "yes"

    def test_other_value_is_yes(self):
        assert _known_hosts_mode({"known_hosts_policy": "no"}) == "yes"


class TestBaseSshCmd:
    def test_default_port(self):
        cmd = _base_ssh_cmd({"username": "root"})
        assert "-p" in cmd
        idx = cmd.index("-p")
        assert cmd[idx + 1] == "22"

    def test_custom_port(self):
        cmd = _base_ssh_cmd({"port": 2222})
        idx = cmd.index("-p")
        assert cmd[idx + 1] == "2222"

    def test_batch_mode(self):
        cmd = _base_ssh_cmd({})
        assert "BatchMode=no" in cmd

    def test_strict_host_key_checking(self):
        cmd = _base_ssh_cmd({"known_hosts_policy": "accept_new"})
        assert "StrictHostKeyChecking=accept-new" in cmd

    def test_connect_timeout(self):
        cmd = _base_ssh_cmd({})
        assert "ConnectTimeout=10" in cmd


class TestPrepareSsh:
    def test_basic_command(self):
        config = {"host": "10.0.0.1", "username": "root", "password": "secret"}
        ssh_cmd, env, temp_files = _prepare_ssh(config, "id")
        assert ssh_cmd[0] == "ssh"
        assert "root@10.0.0.1" in ssh_cmd
        assert "id" in ssh_cmd

    def test_private_key_creates_temp_file(self):
        config = {"host": "10.0.0.1", "username": "root", "private_key": "-----BEGIN KEY-----\ntest\n-----END KEY-----"}
        ssh_cmd, env, temp_files = _prepare_ssh(config, "ls")
        assert any("-i" == ssh_cmd[i] for i in range(len(ssh_cmd)))
        assert len(temp_files) >= 1

    def test_password_sets_askpass_env(self):
        config = {"host": "10.0.0.1", "username": "root", "password": "secret"}
        _, env, _ = _prepare_ssh(config, "ls")
        assert "RT_SSH_PASSWORD" in env
        assert env["RT_SSH_PASSWORD"] == "secret"
        assert "SSH_ASKPASS" in env

    def test_jump_proxy(self):
        config = {
            "host": "10.0.0.2", "username": "root", "password": "pass",
            "proxy_type": "jump",
            "proxy_host": "10.0.0.1", "proxy_port": 22,
            "proxy_username": "jumphost", "proxy_password": "jpass",
        }
        ssh_cmd, env, temp_files = _prepare_ssh(config, "ls")
        proxy_cmd_parts = [p for p in ssh_cmd if "ProxyCommand" in str(p)]
        assert len(proxy_cmd_parts) > 0
        assert "RT_SSH_PROXY_PASSWORD" in env

    def test_socks5_proxy(self):
        config = {
            "host": "10.0.0.2", "username": "root", "password": "pass",
            "proxy_type": "socks5",
            "proxy_host": "127.0.0.1", "proxy_port": 1080,
            "proxy_username": "user", "proxy_password": "pass",
        }
        ssh_cmd, env, temp_files = _prepare_ssh(config, "ls")
        proxy_parts = [p for p in ssh_cmd if "ProxyCommand" in str(p)]
        assert len(proxy_parts) > 0

    def test_no_proxy(self):
        config = {"host": "10.0.0.1", "username": "root", "password": "pass", "proxy_type": "none"}
        ssh_cmd, env, temp_files = _prepare_ssh(config, "ls")
        assert not any("ProxyCommand" in str(p) for p in ssh_cmd)

    def test_appends_user_host_and_command(self):
        config = {"host": "10.0.0.1", "username": "admin"}
        ssh_cmd, _, _ = _prepare_ssh(config, "whoami")
        assert ssh_cmd[-2] == "admin@10.0.0.1"
        assert ssh_cmd[-1] == "whoami"


class TestIsTransportFailure:
    def test_non_255_is_not_failure(self):
        assert is_transport_failure({"exit_code": 0}) is False
        assert is_transport_failure({"exit_code": 1}) is False

    def test_transport_error_detected(self):
        for err_str in _TRANSPORT_ERROR_STRINGS:
            result = {"exit_code": 255, "stderr": f"Error: {err_str}"}
            assert is_transport_failure(result) is True

    def test_auth_failure_not_transport(self):
        result = {"exit_code": 255, "stderr": "Permission denied (publickey)."}
        assert is_transport_failure(result) is False

    def test_empty_stderr(self):
        result = {"exit_code": 255, "stderr": ""}
        assert is_transport_failure(result) is False

    def test_none_stderr(self):
        result = {"exit_code": 255, "stderr": None}
        assert is_transport_failure(result) is False

    def test_mixed_errors(self):
        result = {"exit_code": 255, "stderr": "Connection timed out\nPermission denied"}
        assert is_transport_failure(result) is True


# ════════ from test_core_ssh_exec_extended.py ════════
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
