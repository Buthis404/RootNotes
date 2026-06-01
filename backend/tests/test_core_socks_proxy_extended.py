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
