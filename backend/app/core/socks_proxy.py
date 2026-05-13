import argparse
import select
import socket
import struct
import sys


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks = []
    remaining = length
    while remaining > 0:
        data = sock.recv(remaining)
        if not data:
            raise RuntimeError("SOCKS proxy closed connection")
        chunks.append(data)
        remaining -= len(data)
    return b"".join(chunks)


def _negotiate(sock: socket.socket, target_host: str, target_port: int, username: str = "", password: str = ""):
    methods = [0x00]
    if username or password:
        methods = [0x02]
    sock.sendall(bytes([0x05, len(methods), *methods]))
    version, method = _recv_exact(sock, 2)
    if version != 0x05:
        raise RuntimeError("Invalid SOCKS5 proxy response")
    if method == 0xFF:
        raise RuntimeError("SOCKS5 proxy does not accept requested auth method")
    if method == 0x02:
        u = username.encode()
        p = password.encode()
        if len(u) > 255 or len(p) > 255:
            raise RuntimeError("SOCKS5 username/password too long")
        sock.sendall(bytes([0x01, len(u)]) + u + bytes([len(p)]) + p)
        auth_ver, status = _recv_exact(sock, 2)
        if auth_ver != 0x01 or status != 0x00:
            raise RuntimeError("SOCKS5 authentication failed")

    host_bytes = target_host.encode()
    if len(host_bytes) > 255:
        raise RuntimeError("Target hostname too long for SOCKS5")
    req = bytes([0x05, 0x01, 0x00, 0x03, len(host_bytes)]) + host_bytes + struct.pack(">H", target_port)
    sock.sendall(req)

    head = _recv_exact(sock, 4)
    ver, rep, _rsv, atyp = head
    if ver != 0x05:
        raise RuntimeError("Invalid SOCKS5 connect response")
    if rep != 0x00:
        raise RuntimeError(f"SOCKS5 connect failed with code {rep}")
    if atyp == 0x01:
        _recv_exact(sock, 4)
    elif atyp == 0x03:
        length = _recv_exact(sock, 1)[0]
        _recv_exact(sock, length)
    elif atyp == 0x04:
        _recv_exact(sock, 16)
    _recv_exact(sock, 2)


def _relay(sock: socket.socket):
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    inputs = [sock, stdin]
    while True:
        readable, _, _ = select.select(inputs, [], [])
        if sock in readable:
            data = sock.recv(65536)
            if not data:
                break
            stdout.write(data)
            stdout.flush()
        if stdin in readable:
            data = stdin.read1(65536)
            if not data:
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                inputs.remove(stdin)
                if len(inputs) == 1:
                    continue
            else:
                sock.sendall(data)


def main():
    parser = argparse.ArgumentParser(description="SOCKS5 ProxyCommand helper")
    parser.add_argument("target_host")
    parser.add_argument("target_port", type=int)
    parser.add_argument("proxy_host")
    parser.add_argument("proxy_port", type=int)
    parser.add_argument("--username", default="")
    parser.add_argument("--password", default="")
    args = parser.parse_args()

    try:
        with socket.create_connection((args.proxy_host, args.proxy_port), timeout=15) as sock:
            _negotiate(sock, args.target_host, args.target_port, args.username, args.password)
            _relay(sock)
    except Exception as exc:
        print(f"SOCKS5 proxy error: {exc}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
