"""Consolidated tests for test_core_socks_proxy (merged variant files)."""

# ════════ from test_core_socks_proxy.py ════════
import socket
import struct
from unittest.mock import MagicMock, patch

import pytest

from app.core.socks_proxy import (
    _recv_exact,
    _socks5_auth,
    _socks5_skip_reply_addr,
    _negotiate,
    _relay_stdin_to_sock,
)


class TestRecvExact:
    def test_reads_exact_length(self):
        sock = MagicMock()
        sock.recv.side_effect = [b"ab", b"c"]
        result = _recv_exact(sock, 3)
        assert result == b"abc"

    def test_raises_on_empty(self):
        sock = MagicMock()
        sock.recv.return_value = b""
        with pytest.raises(RuntimeError, match="closed"):
            _recv_exact(sock, 5)

    def test_single_chunk(self):
        sock = MagicMock()
        sock.recv.return_value = b"hello"
        assert _recv_exact(sock, 5) == b"hello"


class TestSocks5Auth:
    def test_successful_auth(self):
        sock = MagicMock()
        sock.recv.return_value = bytes([0x01, 0x00])
        _socks5_auth(sock, "user", "pass")
        sock.sendall.assert_called_once()

    def test_auth_failed(self):
        sock = MagicMock()
        sock.recv.return_value = bytes([0x01, 0x01])
        with pytest.raises(RuntimeError, match="authentication failed"):
            _socks5_auth(sock, "user", "pass")

    def test_too_long_username(self):
        with pytest.raises(RuntimeError, match="too long"):
            _socks5_auth(MagicMock(), "x" * 256, "pass")

    def test_too_long_password(self):
        with pytest.raises(RuntimeError, match="too long"):
            _socks5_auth(MagicMock(), "u", "x" * 256)


class TestSocks5SkipReplyAddr:
    def test_ipv4(self):
        sock = MagicMock()
        sock.recv.side_effect = [b"\x00\x00\x00\x00", b"\x00\x00"]
        _socks5_skip_reply_addr(sock, 0x01)
        assert sock.recv.call_count == 2

    def test_domain(self):
        sock = MagicMock()
        sock.recv.side_effect = [b"\x04", b"test", b"\x00\x00"]
        _socks5_skip_reply_addr(sock, 0x03)
        assert sock.recv.call_count == 3

    def test_ipv6(self):
        sock = MagicMock()
        sock.recv.side_effect = [b"\x00" * 16, b"\x00\x00"]
        _socks5_skip_reply_addr(sock, 0x04)
        assert sock.recv.call_count == 2


class TestNegotiate:
    def test_invalid_version(self):
        sock = MagicMock()
        sock.recv.return_value = bytes([0x04, 0x00])
        with pytest.raises(RuntimeError, match="Invalid SOCKS5"):
            _negotiate(sock, "host", 80)

    def test_no_acceptable_method(self):
        sock = MagicMock()
        sock.recv.return_value = bytes([0x05, 0xFF])
        with pytest.raises(RuntimeError, match="does not accept"):
            _negotiate(sock, "host", 80)

    def test_hostname_too_long(self):
        sock = MagicMock()
        sock.recv.side_effect = [bytes([0x05, 0x00]), bytes([0x05, 0x00, 0x00, 0x01])]
        with patch("app.core.socks_proxy._socks5_skip_reply_addr"):
            with pytest.raises(RuntimeError, match="too long"):
                _negotiate(sock, "x" * 300, 80)

    def test_successful_no_auth(self):
        responses = [
            bytes([0x05, 0x00]),
            bytes([0x05, 0x00, 0x00, 0x01]),
        ]
        sock = MagicMock()
        sock.recv.side_effect = responses
        with patch("app.core.socks_proxy._socks5_skip_reply_addr"):
            _negotiate(sock, "target", 80)
        assert sock.sendall.call_count == 2

    def test_successful_with_auth(self):
        responses = [
            bytes([0x05, 0x02]),
            bytes([0x05, 0x00, 0x00, 0x01]),
        ]
        sock = MagicMock()
        sock.recv.side_effect = responses
        with patch("app.core.socks_proxy._socks5_auth"), \
             patch("app.core.socks_proxy._socks5_skip_reply_addr"):
            _negotiate(sock, "target", 80, "u", "p")

    def test_connect_failure(self):
        responses = [
            bytes([0x05, 0x00]),
            bytes([0x05, 0x01, 0x00, 0x01]),
        ]
        sock = MagicMock()
        sock.recv.side_effect = responses
        with pytest.raises(RuntimeError, match="connect failed"):
            _negotiate(sock, "target", 80)


class TestRelayStdinToSock:
    def test_exhausted_stdin(self):
        stdin = MagicMock()
        stdin.read1.return_value = b""
        sock = MagicMock()
        inputs = [stdin, sock]
        result = _relay_stdin_to_sock(stdin, sock, inputs)
        assert result is True
        assert stdin not in inputs

    def test_data_forwarded(self):
        stdin = MagicMock()
        stdin.read1.return_value = b"data"
        sock = MagicMock()
        inputs = [stdin, sock]
        result = _relay_stdin_to_sock(stdin, sock, inputs)
        assert result is False
        sock.sendall.assert_called_once_with(b"data")


# ════════ from test_core_socks_proxy_extended.py ════════
import socket
from unittest.mock import MagicMock, patch

import pytest

from app.core.socks_proxy import _relay_stdin_to_sock, _relay, main


class TestRelayStdinShutdownOSError:
    def test_shutdown_oserror_ignored(self):
        stdin = MagicMock()
        stdin.read1.return_value = b""
        sock = MagicMock()
        sock.shutdown.side_effect = OSError("not connected")
        inputs = [stdin, sock]
        result = _relay_stdin_to_sock(stdin, sock, inputs)
        assert result is True
        assert stdin not in inputs


class TestRelayLoop:
    def test_relay_reads_from_sock_and_writes_stdout(self):
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"data"
        call_count = [0]

        def fake_select(inputs, _, __):
            nonlocal call_count
            call_count[0] += 1
            if call_count[0] == 1:
                return [mock_sock], [], []
            mock_sock.recv.return_value = b""
            return [mock_sock], [], []

        with patch("app.core.socks_proxy.sys") as mock_sys, \
             patch("app.core.socks_proxy.select") as mock_sel, \
             patch("app.core.socks_proxy._relay_stdin_to_sock"):
            mock_sys.stdin.buffer = mock_stdin
            mock_sys.stdout.buffer = mock_stdout
            mock_sel.select.side_effect = fake_select
            _relay(mock_sock)
        mock_stdout.write.assert_called_with(b"data")
        mock_stdout.flush.assert_called()


class TestMainFunction:
    def test_main_raises_on_connection_failure(self):
        with pytest.raises(SystemExit):
            with patch("app.core.socks_proxy.argparse") as mock_ap:
                mock_parser = MagicMock()
                mock_ap.ArgumentParser.return_value = mock_parser
                mock_args = MagicMock()
                mock_args.proxy_host = "127.0.0.1"
                mock_args.proxy_port = 1080
                mock_args.target_host = "target"
                mock_args.target_port = 80
                mock_args.username = ""
                mock_args.password = ""
                mock_parser.parse_args.return_value = mock_args
                with patch("app.core.socks_proxy.socket.create_connection", side_effect=Exception("fail")):
                    main()
