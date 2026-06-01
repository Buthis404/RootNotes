"""Extended pivots tests — parser helpers and scope functions."""
import ipaddress
from unittest.mock import MagicMock

from app.routers.pivots import (
    _parse_one_chisel_forward,
    _parse_chisel_args,
    _parse_ligolo_args,
    _format_params_note,
    _extract_params_from_notes,
    _parse_ss_lines,
    _parse_routes,
    _normalize_cidr,
    _format_bind_address,
    _observation_scope_decision,
    _ip_in_any_scope,
    _cidr_in_any_scope,
    _load_project_scope_networks,
    normalize_pivot_proxy_type,
)


class TestParseOneChiselForward:
    def test_socks_reverse(self):
        import re
        m = re.search(r"(?P<dir>[RL]):(?P<spec>[^\s]+)", "R:socks")
        result = _parse_one_chisel_forward(m)
        assert result["direction"] == "reverse"
        assert result["proxy_type"] == "socks"

    def test_tcp_forward(self):
        import re
        m = re.search(r"(?P<dir>[RL]):(?P<spec>[^\s]+)", "R:127.0.0.1:8443:10.0.0.1:443")
        result = _parse_one_chisel_forward(m)
        assert result["direction"] == "reverse"
        assert result["proxy_type"] == "tcp"
        assert result["target_host"] == "10.0.0.1"
        assert result["target_port"] == 443

    def test_local_forward(self):
        import re
        m = re.search(r"(?P<dir>[RL]):(?P<spec>[^\s]+)", "L:8080:internal:80")
        result = _parse_one_chisel_forward(m)
        assert result["direction"] == "local"


class TestParseChiselArgs:
    def test_server_reverse(self):
        result = _parse_chisel_args("chisel server --reverse")
        assert result["mode"] == "server"
        assert result["direction"] == "reverse"

    def test_client(self):
        result = _parse_chisel_args("chisel client https://attacker:8080 R:socks")
        assert result["mode"] == "client"
        assert result["server"] == "https://attacker:8080"

    def test_server_no_reverse(self):
        result = _parse_chisel_args("chisel server")
        assert result["mode"] == "server"


class TestParseLigoloArgs:
    def test_proxy(self):
        result = _parse_ligolo_args("ligolo proxy -selfcert -laddr 0.0.0.0:11601")
        assert result["mode"] == "proxy"
        assert result["listen"] == "0.0.0.0:11601"

    def test_agent(self):
        result = _parse_ligolo_args("ligolo agent -connect 10.0.0.1:11601")
        assert result["mode"] == "agent"
        assert result["server"] == "10.0.0.1:11601"


class TestFormatParamsNote:
    def test_empty_params(self):
        assert _format_params_note("raw", {}) == "raw"[:600]

    def test_with_params(self):
        result = _format_params_note("raw line", {"mode": "client"})
        assert "#params:" in result
        assert "raw line" in result


class TestExtractParamsFromNotes:
    def test_no_params(self):
        assert _extract_params_from_notes("no params here") == {}

    def test_valid_params(self):
        import json
        params = {"mode": "client"}
        notes = f"line\n#params: {json.dumps(params)}"
        result = _extract_params_from_notes(notes)
        assert result["mode"] == "client"

    def test_invalid_json(self):
        assert _extract_params_from_notes("line\n#params: {bad json}") == {}


class TestParseSsLines:
    def test_parses_ports(self):
        lines = [
            'LISTEN  0  128  0.0.0.0:1080  0.0.0.0:*  users:(("chisel",pid=1234,fd=3))',
        ]
        result = _parse_ss_lines(lines)
        assert "chisel" in result
        assert 1080 in result["chisel"]

    def test_no_match(self):
        lines = ["LISTEN 0 128 0.0.0.0:80 0.0.0.0:* users:((\"nginx\",pid=1,fd=3))"]
        result = _parse_ss_lines(lines)
        assert len(result) == 0


class TestParseRoutes:
    def test_parses_cidr(self):
        lines = ["10.0.0.0/24 via 192.168.1.1", "0.0.0.0/0 via 10.0.0.1"]
        routes = _parse_routes(lines)
        assert "10.0.0.0/24" in routes
        assert "0.0.0.0/0" not in routes

    def test_no_routes(self):
        assert _parse_routes(["no cidr here"]) == []


class TestNormalizeCidr:
    def test_valid(self):
        assert _normalize_cidr("10.0.0.0/24") == "10.0.0.0/24"

    def test_invalid(self):
        assert _normalize_cidr("not a cidr") == ""

    def test_strips(self):
        assert _normalize_cidr("  10.0.0.0/24  ") == "10.0.0.0/24"


class TestFormatBindAddress:
    def test_both(self):
        assert _format_bind_address("0.0.0.0", "1080") == "0.0.0.0:1080"

    def test_port_only(self):
        assert _format_bind_address("", "1080") == "1080"

    def test_empty(self):
        assert _format_bind_address("", "") == ""


class TestNormalizePivotProxyType:
    def test_socks5(self):
        assert normalize_pivot_proxy_type("SOCKS5") == "socks5"

    def test_socks4(self):
        assert normalize_pivot_proxy_type("socks4") == "socks4"

    def test_other(self):
        assert normalize_pivot_proxy_type("tcp") == "tcp"


class TestIpInAnyScope:
    def test_in_scope(self):
        nets = [ipaddress.ip_network("10.0.0.0/24")]
        assert _ip_in_any_scope("10.0.0.5", nets) is True

    def test_out_of_scope(self):
        nets = [ipaddress.ip_network("10.0.0.0/24")]
        assert _ip_in_any_scope("192.168.1.1", nets) is False

    def test_invalid_ip(self):
        assert _ip_in_any_scope("not-an-ip", []) is None


class TestCidrInAnyScope:
    def test_overlaps(self):
        nets = [ipaddress.ip_network("10.0.0.0/24")]
        assert _cidr_in_any_scope("10.0.0.0/25", nets) is True

    def test_no_overlap(self):
        nets = [ipaddress.ip_network("10.0.0.0/24")]
        assert _cidr_in_any_scope("192.168.0.0/24", nets) is False

    def test_invalid(self):
        assert _cidr_in_any_scope("bad", []) is None


class TestObservationScopeDecision:
    def test_no_scopes_is_in_scope(self):
        assert _observation_scope_decision({}, []) == "in_scope"

    def test_route_in_scope(self):
        nets = [ipaddress.ip_network("10.0.0.0/24")]
        item = {"route_cidr": "10.0.0.0/25", "notes": ""}
        assert _observation_scope_decision(item, nets) == "in_scope"

    def test_route_out_of_scope(self):
        nets = [ipaddress.ip_network("10.0.0.0/24")]
        item = {"route_cidr": "192.168.0.0/24", "notes": ""}
        assert _observation_scope_decision(item, nets) == "out_of_scope"

    def test_no_targeting_info(self):
        nets = [ipaddress.ip_network("10.0.0.0/24")]
        item = {"route_cidr": "", "notes": ""}
        assert _observation_scope_decision(item, nets) == "ambiguous"
