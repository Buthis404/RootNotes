"""
Tests for the chisel / ligolo-ng PS+ss parsers in pivots.py.

These are pure-function tests against the parser helpers; no SSH
collector is actually invoked.
"""
import json

import pytest

from app.routers.pivots import (
    _parse_chisel_args,
    _parse_ligolo_args,
    _parse_ss_lines,
    _parse_tool_observations,
)


# ── chisel arg parsing ──────────────────────────────────────────────

def test_chisel_client_reverse_socks():
    out = _parse_chisel_args("/opt/chisel client https://attacker:8443 R:socks")
    assert out["mode"] == "client"
    assert out["server"] == "https://attacker:8443"
    assert out["direction"] == "reverse"
    assert out["proxy_type"] == "socks"
    assert any(f["proxy_type"] == "socks" for f in out["forwards"])


def test_chisel_client_local_port_forward():
    out = _parse_chisel_args("./chisel client 10.0.0.1:80 L:8080:internal.local:80")
    assert out["mode"] == "client"
    assert out["direction"] == "local"
    assert out["proxy_type"] == "tcp"
    assert out["forwards"][0]["raw"].startswith("L:")


def test_chisel_server_reverse_listener():
    out = _parse_chisel_args("/usr/local/bin/chisel server -p 8080 --reverse")
    assert out["mode"] == "server"
    assert out["direction"] == "reverse"


def test_chisel_unrelated_line_is_empty_dict():
    assert _parse_chisel_args("/usr/sbin/sshd -D") == {}


# ── ligolo arg parsing ──────────────────────────────────────────────

def test_ligolo_agent_with_connect():
    out = _parse_ligolo_args("./agent -connect 10.10.14.5:11601 -ignore-cert")
    assert out["mode"] == "agent"
    assert out["server"] == "10.10.14.5:11601"


def test_ligolo_proxy_with_laddr():
    out = _parse_ligolo_args("/opt/ligolo/proxy -selfcert -laddr 0.0.0.0:11601")
    assert out["mode"] == "proxy"
    assert out["listen"] == "0.0.0.0:11601"


def test_ligolo_interface_from_ip_route_style_line():
    out = _parse_ligolo_args("ip route add 10.0.0.0/16 dev ligolo")
    assert out["interface"] == "ligolo"


def test_ligolo_unrelated_line_is_empty():
    assert _parse_ligolo_args("/usr/sbin/sshd -D") == {}


# ── ss -tnlp parsing ────────────────────────────────────────────────

def test_ss_lines_extract_listen_ports():
    lines = [
        'LISTEN 0      4096       0.0.0.0:1080      0.0.0.0:*    users:(("chisel",pid=1234,fd=3))',
        'LISTEN 0      4096       0.0.0.0:8080      0.0.0.0:*    users:(("chisel",pid=1234,fd=5))',
        'LISTEN 0      4096       0.0.0.0:11601     0.0.0.0:*    users:(("proxy",pid=2222,fd=7))',
        'LISTEN 0      4096       127.0.0.1:22      0.0.0.0:*    users:(("sshd",pid=10,fd=3))',
    ]
    out = _parse_ss_lines(lines)
    assert sorted(out["chisel"]) == [1080, 8080]
    assert out["proxy"] == [11601]
    assert "sshd" not in out


# ── End-to-end observation shape ────────────────────────────────────

def test_observation_includes_parsed_params_trailer():
    ps_lines = ["/opt/chisel client https://attacker:8443 R:socks"]
    route_lines = ["10.0.0.0/24 dev tun0"]
    ss_lines = ['LISTEN 0 4096 0.0.0.0:1080 0.0.0.0:* users:(("chisel",pid=1,fd=3))']

    obs = _parse_tool_observations(ps_lines, route_lines, ss_lines)
    assert len(obs) == 1
    o = obs[0]
    assert o["tool"] == "chisel"
    assert o["pivot_type"] == "socks5"
    assert o["route_cidr"] == "10.0.0.0/24"
    # bind_address now prefers the server URL when available
    assert o["bind_address"] == "https://attacker:8443"
    # label is more descriptive
    assert "client" in o["label"]
    assert "reverse" in o["label"]
    # the JSON-encoded params trailer is in notes
    assert "#params:" in o["notes"]
    params_line = o["notes"].split("#params: ", 1)[1]
    params = json.loads(params_line)
    assert params["mode"] == "client"
    assert params["live_listen_ports"] == [1080]


def test_observation_ligolo_agent():
    ps_lines = ["./agent -connect 10.10.14.5:11601"]
    obs = _parse_tool_observations(ps_lines, [], [])
    assert len(obs) == 1
    o = obs[0]
    assert o["tool"] == "ligolo"
    assert o["bind_address"] == "10.10.14.5:11601"
    assert "agent" in o["label"]


def test_observation_emits_one_row_per_route():
    ps_lines = ["./chisel client server R:socks"]
    route_lines = ["10.0.0.0/24 dev tun0", "192.168.1.0/24 dev tun0"]
    obs = _parse_tool_observations(ps_lines, route_lines, [])
    cidrs = sorted(o["route_cidr"] for o in obs)
    assert cidrs == ["10.0.0.0/24", "192.168.1.0/24"]


def test_observation_skips_unrelated_processes():
    ps_lines = ["/usr/sbin/sshd -D", "bash -c whoami"]
    obs = _parse_tool_observations(ps_lines, [], [])
    assert obs == []
