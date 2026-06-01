"""Consolidated tests for test_pivots (merged variant files)."""

# ════════ from test_pivots_api.py ════════
import ipaddress
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
TS = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    r = module_client.post("/api/projects", json={"name": "PivotTest", "added": TS, "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]

    r = module_client.post("/api/hosts", json={
        "pid": _state["pid"], "ip": "10.60.60.1", "hostname": "pivot-host",
        "os": "Linux", "status": "alive", "role": "router",
    })
    assert r.status_code == 201
    _state["hid"] = r.json()["id"]

    r = module_client.post("/api/hosts", json={
        "pid": _state["pid"], "ip": "10.60.60.100", "hostname": "pivot-attacker",
        "os": "Kali", "status": "attacker", "role": "attacker", "is_attacker": True,
    })
    assert r.status_code == 201
    _state["att_hid"] = r.json()["id"]

    yield
    module_client.post("/api/auth/logout")


class TestPivotCRUD:
    def test_create_pivot(self, module_client: TestClient):
        r = module_client.post(
            f"/api/projects/{_state['pid']}/pivots",
            json={
                "pid": _state["pid"],
                "source_host_id": _state["att_hid"],
                "pivot_host_id": _state["hid"],
                "target_host_id": "",
                "tool": "chisel",
                "pivot_type": "socks5",
                "label": "test pivot",
                "route_cidr": "10.60.60.0/24",
                "bind_address": "127.0.0.1:1080",
                "status": "active",
                "notes": "test",
            },
        )
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["tool"] == "chisel"
        assert data["pivot_type"] == "socks5"
        _state["pvt_id"] = data["id"]

    def test_list_pivots(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/pivots")
        assert r.status_code == 200
        data = r.json()
        assert len(data["items"]) >= 1
        ids = [item["id"] for item in data["items"]]
        assert _state["pvt_id"] in ids

    def test_update_pivot(self, module_client: TestClient):
        r = module_client.patch(
            f"/api/projects/{_state['pid']}/pivots/{_state['pvt_id']}",
            json={"status": "inactive", "notes": "updated"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "inactive"

    def test_delete_pivot(self, module_client: TestClient):
        r = module_client.delete(f"/api/projects/{_state['pid']}/pivots/{_state['pvt_id']}")
        assert r.status_code == 204

    def test_delete_pivot_404(self, module_client: TestClient):
        r = module_client.delete(f"/api/projects/{_state['pid']}/pivots/nonexistent")
        assert r.status_code == 404

    def test_create_pivot_pid_mismatch(self, module_client: TestClient):
        r = module_client.post(
            f"/api/projects/{_state['pid']}/pivots",
            json={
                "pid": "other-pid",
                "pivot_host_id": _state["hid"],
                "tool": "chisel",
                "pivot_type": "socks5",
                "status": "active",
            },
        )
        assert r.status_code == 400


class TestPivotCollect:
    def test_collect_requires_target(self, module_client: TestClient):
        r = module_client.post(
            f"/api/projects/{_state['pid']}/pivots/collect",
            json={"target_id": "", "source_host_id": ""},
        )
        assert r.status_code in (400, 404, 500)


class TestPivotHelpers:
    def test_parse_routes(self):
        from app.routers.pivots import _parse_routes
        routes = _parse_routes([
            "10.0.0.0/24 via 192.168.1.1",
            "172.16.0.0/16 dev eth0",
            "default via 10.0.0.1",
        ])
        assert "10.0.0.0/24" in routes
        assert "172.16.0.0/16" in routes

    def test_parse_routes_no_default(self):
        from app.routers.pivots import _parse_routes
        routes = _parse_routes(["0.0.0.0/0 via 10.0.0.1"])
        assert "0.0.0.0/0" not in routes

    def test_parse_chisel_args(self):
        from app.routers.pivots import _parse_chisel_args
        result = _parse_chisel_args("chisel client https://attacker:8080 R:socks")
        assert result.get("mode") == "client"
        assert result.get("server") == "https://attacker:8080"

    def test_parse_ligolo_args(self):
        from app.routers.pivots import _parse_ligolo_args
        result = _parse_ligolo_args("ligolo-proxy -selfcert -laddr 0.0.0.0:11601")
        assert result.get("mode") == "proxy"
        assert result.get("listen") == "0.0.0.0:11601"

    def test_normalize_pivot_proxy_type(self):
        from app.routers.pivots import normalize_pivot_proxy_type
        assert normalize_pivot_proxy_type("SOCKS5") == "socks5"
        assert normalize_pivot_proxy_type("socks4") == "socks4"
        assert normalize_pivot_proxy_type("tcp") == "tcp"

    def test_format_bind_address(self):
        from app.routers.pivots import _format_bind_address
        assert _format_bind_address("127.0.0.1", "1080") == "127.0.0.1:1080"
        assert _format_bind_address("", "1080") == "1080"
        assert _format_bind_address("127.0.0.1", "") == "127.0.0.1"
        assert _format_bind_address("", "") == ""

    def test_normalize_cidr(self):
        from app.routers.pivots import _normalize_cidr
        assert _normalize_cidr("10.0.0.0/24") == "10.0.0.0/24"
        assert _normalize_cidr("invalid") == ""

    def test_cidr_in_any_scope(self):
        from app.routers.pivots import _cidr_in_any_scope
        scopes = [ipaddress.ip_network("10.0.0.0/8")]
        assert _cidr_in_any_scope("10.0.0.0/24", scopes) is True
        assert _cidr_in_any_scope("192.168.0.0/24", scopes) is False

    def test_ip_in_any_scope(self):
        from app.routers.pivots import _ip_in_any_scope
        scopes = [ipaddress.ip_network("10.0.0.0/8")]
        assert _ip_in_any_scope("10.0.0.1", scopes) is True
        assert _ip_in_any_scope("192.168.1.1", scopes) is False
        assert _ip_in_any_scope("invalid", scopes) is None

    def test_observation_scope_decision(self):
        from app.routers.pivots import _observation_scope_decision
        scopes = [ipaddress.ip_network("10.0.0.0/8")]
        item = {"route_cidr": "10.0.0.0/24", "notes": ""}
        assert _observation_scope_decision(item, scopes) == "in_scope"

        item2 = {"route_cidr": "192.168.0.0/24", "notes": ""}
        assert _observation_scope_decision(item2, scopes) == "out_of_scope"

        item3 = {"route_cidr": "", "notes": ""}
        assert _observation_scope_decision(item3, scopes) == "ambiguous"

        assert _observation_scope_decision({}, []) == "in_scope"

    def test_parse_tool_observations(self):
        from app.routers.pivots import _parse_tool_observations
        ps_lines = ["chisel client https://attacker:8080 R:socks"]
        route_lines = ["10.0.0.0/24 via 192.168.1.1"]
        obs = _parse_tool_observations(ps_lines, route_lines)
        assert len(obs) >= 1
        assert obs[0]["tool"] == "chisel"

    def test_parse_ss_lines(self):
        from app.routers.pivots import _parse_ss_lines
        lines = [
            'LISTEN 0 128 0.0.0.0:1080 *:* users:(("chisel",pid=1234,fd=3))',
        ]
        result = _parse_ss_lines(lines)
        assert "chisel" in result
        assert 1080 in result["chisel"]

    def test_extract_params_from_notes(self):
        from app.routers.pivots import _extract_params_from_notes
        notes = "chisel client ...\n#params: {\"mode\":\"client\"}"
        params = _extract_params_from_notes(notes)
        assert params["mode"] == "client"

    def test_extract_params_from_notes_empty(self):
        from app.routers.pivots import _extract_params_from_notes
        assert _extract_params_from_notes("no params") == {}

    def test_format_params_note(self):
        from app.routers.pivots import _format_params_note
        result = _format_params_note("chisel line", {"mode": "client"})
        assert "#params:" in result
        assert "client" in result

    def test_format_params_note_empty(self):
        from app.routers.pivots import _format_params_note
        result = _format_params_note("plain line", {})
        assert "#params:" not in result


# ════════ from test_pivots_extended.py ════════
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
