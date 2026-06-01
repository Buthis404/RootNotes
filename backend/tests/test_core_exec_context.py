"""Tests for app.core.exec_context — remote execution command builder."""

from app.core.exec_context import (
    _build_jump_host_exports,
    _build_proxy_exports,
    _wrap_with_proxychains,
    build_remote_execution_command,
)


class TestBuildJumpHostExports:
    def test_with_username(self):
        exports = _build_jump_host_exports("10.0.0.1", "root", 22)
        assert len(exports) == 4
        assert "ROOTNOTES_EXEC_JUMP_HOST=10.0.0.1" in exports[0]
        assert "ROOTNOTES_EXEC_JUMP_PORT=22" in exports[1]
        assert "ROOTNOTES_EXEC_JUMP_USERNAME=root" in exports[2]
        assert "-J root@10.0.0.1:22" in exports[3]

    def test_without_username(self):
        exports = _build_jump_host_exports("10.0.0.1", "", 2222)
        assert "-J 10.0.0.1:2222" in exports[3]


class TestBuildProxyExports:
    def test_socks5(self):
        exports = _build_proxy_exports("socks5", "127.0.0.1", 1080, "user", "pass")
        assert len(exports) == 5
        assert "ROOTNOTES_EXEC_PROXY_TYPE=socks5" in exports[0]
        assert "ROOTNOTES_EXEC_PROXY_HOST=127.0.0.1" in exports[1]
        assert "ROOTNOTES_EXEC_PROXY_PORT=1080" in exports[2]

    def test_empty_credentials(self):
        exports = _build_proxy_exports("http", "10.0.0.1", 8080, "", "")
        assert "ROOTNOTES_EXEC_PROXY_USERNAME=''" in exports[3]


class TestWrapWithProxychains:
    def test_basic_wrap(self):
        result = _wrap_with_proxychains("nmap -sV 10.0.0.1", "socks5", "127.0.0.1", 1080, "", "")
        assert "proxychains4" in result or "proxychains" in result
        assert "nmap" in result

    def test_with_auth(self):
        result = _wrap_with_proxychains("ls", "socks5", "127.0.0.1", 1080, "user", "pass")
        assert "user" in result
        assert "pass" in result


class TestBuildRemoteExecutionCommand:
    def test_empty_command(self):
        assert build_remote_execution_command({}, "   ") == "   "

    def test_plain_command_no_config(self):
        result = build_remote_execution_command({}, "nmap -sV 10.0.0.1")
        assert result == "nmap -sV 10.0.0.1"

    def test_with_jump_host(self):
        config = {"exec_jump_host": "10.0.0.1", "exec_jump_username": "root", "exec_jump_port": 22}
        result = build_remote_execution_command(config, "ls")
        assert "ROOTNOTES_EXEC_JUMP_HOST" in result
        assert "ls" in result

    def test_with_socks_proxy(self):
        config = {
            "exec_proxy_type": "socks5",
            "exec_proxy_host": "127.0.0.1",
            "exec_proxy_port": 1080,
        }
        result = build_remote_execution_command(config, "nmap 10.0.0.1")
        assert "proxychains" in result

    def test_with_http_proxy(self):
        config = {
            "exec_proxy_type": "http",
            "exec_proxy_host": "10.0.0.1",
            "exec_proxy_port": 8080,
        }
        result = build_remote_execution_command(config, "ls")
        assert "ROOTNOTES_EXEC_PROXY_TYPE=http" in result

    def test_jump_and_proxy_combined(self):
        config = {
            "exec_jump_host": "10.0.0.1",
            "exec_jump_username": "root",
            "exec_jump_port": 22,
            "exec_proxy_type": "socks5",
            "exec_proxy_host": "127.0.0.1",
            "exec_proxy_port": 1080,
        }
        result = build_remote_execution_command(config, "whoami")
        assert "ROOTNOTES_EXEC_JUMP_HOST" in result
        assert "proxychains" in result

    def test_proxy_type_none_is_noop(self):
        config = {
            "exec_proxy_type": "none",
            "exec_proxy_host": "10.0.0.1",
        }
        result = build_remote_execution_command(config, "ls")
        assert result == "ls"
