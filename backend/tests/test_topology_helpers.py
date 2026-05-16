"""
Unit tests for pure helpers in app.routers.topology used by Smart Build.

These don't touch the database — they validate the pure functions that
classify hosts, pick junction devices, and compute edge/node references.
"""
import ipaddress

import pytest

from app.routers.topology import (
    _ip_in_network,
    _is_key_host,
    _find_pivot_host,
    _node_ref,
    _edge_ref,
    _node_type_for,
    _infer_node_role,
    _is_gateway,
    _host_matches_gateway_ip,
    _host_scope_memberships,
    _pick_gateway,
    infer_links_smart,
)


# ── _ip_in_network ───────────────────────────────────────────────────

class TestIpInNetwork:
    def test_ipv4_inside(self):
        net = ipaddress.ip_network("10.0.0.0/24")
        assert _ip_in_network("10.0.0.5", net) is True

    def test_ipv4_outside(self):
        net = ipaddress.ip_network("10.0.0.0/24")
        assert _ip_in_network("10.0.1.5", net) is False

    def test_empty_ip(self):
        net = ipaddress.ip_network("10.0.0.0/24")
        assert _ip_in_network("", net) is False

    def test_malformed_ip(self):
        net = ipaddress.ip_network("10.0.0.0/24")
        assert _ip_in_network("not-an-ip", net) is False


# ── _is_key_host ─────────────────────────────────────────────────────

class TestIsKeyHost:
    def test_attacker_flag(self):
        assert _is_key_host({"is_attacker": True}) is True

    def test_attacker_role(self):
        assert _is_key_host({"role": "attacker"}) is True

    def test_dc_role(self):
        assert _is_key_host({"role": "domain_controller"}) is True
        assert _is_key_host({"role": "dc"}) is True

    def test_server_roles(self):
        for role in ("server", "file_server", "web_server", "database",
                     "mail_server", "mail", "jump_host"):
            assert _is_key_host({"role": role}) is True, f"{role} should be key"

    def test_network_device_role(self):
        assert _is_key_host({"role": "network_device"}) is True
        assert _is_key_host({"role": "router"}) is True
        assert _is_key_host({"role": "firewall"}) is True

    def test_server_tag(self):
        assert _is_key_host({"role": "unknown", "tags": ["server"]}) is True

    def test_dc_tag(self):
        assert _is_key_host({"role": "unknown", "tags": ["dc"]}) is True

    def test_vpn_tag(self):
        assert _is_key_host({"role": "unknown", "tags": ["vpn"]}) is True

    def test_plain_workstation_not_key(self):
        h = {"role": "workstation", "tags": []}
        assert _is_key_host(h) is False

    def test_unknown_role_no_tags_not_key(self):
        h = {"role": "unknown", "tags": ["nmap"]}
        assert _is_key_host(h) is False

    def test_empty_dict_not_key(self):
        assert _is_key_host({}) is False

    def test_role_case_insensitive(self):
        assert _is_key_host({"role": "DOMAIN_CONTROLLER"}) is True
        assert _is_key_host({"role": "Router"}) is True


# ── _find_pivot_host ─────────────────────────────────────────────────

@pytest.fixture
def bootcamp_scopes():
    """Two-scope topology mirroring the Test Bootcamp project."""
    entry_net = ipaddress.ip_network("10.124.1.224/27")
    internal_net = ipaddress.ip_network("10.154.16.0/23")
    return [
        {
            "cidr": "10.124.1.224/27", "net_obj": entry_net,
            "gateway_ip": "10.124.1.224", "is_entry": True,
            "via_host_id": "",
        },
        {
            "cidr": "10.154.16.0/23", "net_obj": internal_net,
            "gateway_ip": "10.154.17.1", "is_entry": False,
            "via_host_id": "",
        },
    ]


@pytest.fixture
def bootcamp_hosts():
    return [
        {"id": "h-gw", "ip": "10.124.1.224", "hostname": "GW_EXTERNAL",
         "role": "network_device", "tags": []},
        {"id": "h-vpn", "ip": "10.124.1.253", "hostname": "VPN-GW",
         "role": "network_device", "tags": ["nmap"],
         "ips": ["10.124.1.253", "10.154.17.1"]},
        {"id": "h-dc", "ip": "10.154.16.134", "hostname": "DC",
         "role": "domain_controller", "tags": ["server"]},
        {"id": "h-ws", "ip": "10.154.16.196", "hostname": "SDOTSON",
         "role": "workstation", "tags": []},
    ]


class TestFindPivotHost:
    def test_picks_vpn_gw_over_entry_gateway(self, bootcamp_scopes, bootcamp_hosts):
        """VPN-GW should win — it's network_device with 'vpn' in name and not the entry gw."""
        remote = bootcamp_scopes[1]["net_obj"]
        excluded = {"10.124.1.224"}  # entry gateway is excluded
        pivot = _find_pivot_host(remote, bootcamp_scopes, bootcamp_hosts, excluded)
        assert pivot is not None
        assert pivot["hostname"] == "VPN-GW"

    def test_excludes_entry_gateway(self, bootcamp_scopes, bootcamp_hosts):
        """If only the entry gw qualifies, no pivot is returned."""
        # remove VPN-GW from the host pool — entry gw is excluded so no pivot
        hosts = [h for h in bootcamp_hosts if h["hostname"] != "VPN-GW"]
        remote = bootcamp_scopes[1]["net_obj"]
        excluded = {"10.124.1.224"}
        pivot = _find_pivot_host(remote, bootcamp_scopes, hosts, excluded)
        assert pivot is None

    def test_excludes_host_in_remote_subnet(self, bootcamp_scopes, bootcamp_hosts):
        """A network_device that lives inside the remote subnet is not a 'pivot to' it."""
        # DC is in 10.154.16.0/23 — it's there, not a pivot to itself
        hosts = [{"id": "h-router", "ip": "10.154.16.50",
                  "hostname": "internal-router", "role": "router", "tags": []}]
        remote = bootcamp_scopes[1]["net_obj"]
        pivot = _find_pivot_host(remote, bootcamp_scopes, hosts, {"10.124.1.224"})
        assert pivot is None

    def test_no_junction_device_returns_none(self, bootcamp_scopes):
        """Plain workstations are not junction candidates."""
        hosts = [
            {"id": "h-ws1", "ip": "10.124.1.231", "hostname": "",
             "role": "workstation", "tags": []},
        ]
        remote = bootcamp_scopes[1]["net_obj"]
        pivot = _find_pivot_host(remote, bootcamp_scopes, hosts, {"10.124.1.224"})
        assert pivot is None

    def test_prefers_vpn_in_hostname_over_plain_router(self, bootcamp_scopes):
        """When two candidates match, VPN keyword wins."""
        hosts = [
            {"id": "h-rt", "ip": "10.124.1.240", "hostname": "edge-router-01",
             "role": "router", "tags": []},
            {"id": "h-vpn", "ip": "10.124.1.253", "hostname": "VPN-tunnel",
             "role": "network_device", "tags": []},
        ]
        remote = bootcamp_scopes[1]["net_obj"]
        pivot = _find_pivot_host(remote, bootcamp_scopes, hosts, {"10.124.1.224"})
        assert pivot is not None
        assert pivot["hostname"] == "VPN-tunnel"

    def test_hostname_keyword_alone_is_enough(self, bootcamp_scopes):
        """Even with role=unknown, 'vpn' in hostname makes a host a junction."""
        hosts = [
            {"id": "h", "ip": "10.124.1.240", "hostname": "vpn-edge",
             "role": "unknown", "tags": []},
        ]
        remote = bootcamp_scopes[1]["net_obj"]
        pivot = _find_pivot_host(remote, bootcamp_scopes, hosts, {"10.124.1.224"})
        assert pivot is not None


# ── _is_gateway ──────────────────────────────────────────────────────

class TestIsGateway:
    def test_router_role(self):
        assert _is_gateway({"role": "router"}) is True

    def test_firewall_role(self):
        assert _is_gateway({"role": "firewall"}) is True

    def test_network_device_role(self):
        assert _is_gateway({"role": "network_device"}) is True

    def test_pfsense_os(self):
        assert _is_gateway({"role": "unknown", "os": "pfSense 2.6"}) is True

    def test_router_tag(self):
        assert _is_gateway({"role": "unknown", "tags": ["router"]}) is True

    def test_workstation_not_gateway(self):
        assert _is_gateway({"role": "workstation", "tags": []}) is False


# ── _host_matches_gateway_ip ─────────────────────────────────────────

class TestHostMatchesGatewayIp:
    def test_primary_ip_match(self):
        h = {"ip": "10.0.0.1", "ips": []}
        assert _host_matches_gateway_ip(h, "10.0.0.1") is True

    def test_secondary_ip_match(self):
        h = {"ip": "10.0.0.5", "ips": ["10.0.0.5", "172.16.0.1"]}
        assert _host_matches_gateway_ip(h, "172.16.0.1") is True

    def test_no_match(self):
        h = {"ip": "10.0.0.5", "ips": ["10.0.0.5"]}
        assert _host_matches_gateway_ip(h, "172.16.0.1") is False

    def test_empty_gw(self):
        h = {"ip": "10.0.0.1"}
        assert _host_matches_gateway_ip(h, "") is False


# ── _host_scope_memberships ──────────────────────────────────────────

class TestHostScopeMemberships:
    def test_single_membership(self, bootcamp_scopes):
        h = {"id": "h", "ip": "10.154.16.50", "ips": []}
        members = _host_scope_memberships(h, bootcamp_scopes)
        assert members == ["10.154.16.0/23"]

    def test_multi_homed_dual_membership(self, bootcamp_scopes):
        """VPN-GW with two IPs in different scopes should report both."""
        h = {"id": "h-vpn", "ip": "10.124.1.253",
             "ips": ["10.124.1.253", "10.154.17.1"]}
        members = _host_scope_memberships(h, bootcamp_scopes)
        assert "10.124.1.224/27" in members
        assert "10.154.16.0/23" in members

    def test_no_membership(self, bootcamp_scopes):
        h = {"id": "h", "ip": "8.8.8.8", "ips": []}
        assert _host_scope_memberships(h, bootcamp_scopes) == []


# ── _node_ref / _edge_ref ────────────────────────────────────────────

class TestNodeRef:
    def test_host_id_preferred(self):
        assert _node_ref({"host_id": "hst-1", "ip": "10.0.0.1", "id": "n-1"}) == "hst-1"

    def test_fallback_to_ip(self):
        assert _node_ref({"host_id": "", "ip": "10.0.0.1", "id": "n-1"}) == "10.0.0.1"

    def test_fallback_to_id(self):
        assert _node_ref({"host_id": "", "ip": "", "id": "n-1"}) == "n-1"

    def test_none_returns_empty(self):
        assert _node_ref(None) == ""


class TestEdgeRef:
    def test_canonical_order(self):
        """Edge ref must be order-independent so reverse edges dedupe."""
        a = {"host_id": "hst-a"}
        b = {"host_id": "hst-b"}
        assert _edge_ref(a, b) == _edge_ref(b, a)

    def test_empty_endpoint_returns_empty(self):
        assert _edge_ref({"host_id": ""}, {"host_id": "hst-b"}) == ""


# ── _infer_node_role ─────────────────────────────────────────────────

class TestInferNodeRole:
    def test_attacker_priority(self):
        assert _infer_node_role({"is_attacker": True, "role": "workstation"}) == "attacker"

    def test_dc_by_ports(self):
        h = {"role": "", "ports": ["88/tcp", "389/tcp"], "tags": []}
        assert _infer_node_role(h) == "domain_controller"

    def test_dc_by_role(self):
        assert _infer_node_role({"role": "domain_controller"}) == "domain_controller"
        assert _infer_node_role({"role": "dc"}) == "domain_controller"

    def test_web_server_by_port(self):
        h = {"role": "", "ports": ["443/tcp"], "tags": [], "os": ""}
        assert _infer_node_role(h) == "web_server"

    def test_database_by_port(self):
        h = {"role": "", "ports": ["1433/tcp"], "tags": [], "os": ""}
        assert _infer_node_role(h) == "database"

    def test_windows_workstation(self):
        h = {"role": "", "ports": [], "tags": [], "os": "Windows 10 Pro"}
        assert _infer_node_role(h) == "workstation"

    def test_fallback_to_server(self):
        h = {"role": "", "ports": [], "tags": [], "os": ""}
        assert _infer_node_role(h) == "server"


# ── _node_type_for ───────────────────────────────────────────────────

class TestNodeTypeFor:
    def test_attacker(self):
        assert _node_type_for({"is_attacker": True}) == "attacker"

    def test_router_by_tag(self):
        assert _node_type_for({"role": "", "tags": ["router"], "os": ""}) == "router"

    def test_workstation_windows(self):
        h = {"role": "", "tags": [], "os": "Windows 10"}
        assert _node_type_for(h) == "workstation"

    def test_default_server(self):
        assert _node_type_for({"role": "", "tags": [], "os": ""}) == "server"


# ── _pick_gateway ────────────────────────────────────────────────────

class TestPickGateway:
    def test_explicit_router_role(self):
        group = [
            {"ip": "10.0.0.10", "role": "workstation", "ports": []},
            {"ip": "10.0.0.20", "role": "router", "ports": []},
        ]
        assert _pick_gateway(group)["ip"] == "10.0.0.20"

    def test_gateway_suffix_one(self):
        """IP ending in .1 is preferred when no explicit role."""
        group = [
            {"ip": "10.0.0.10", "role": "", "ports": []},
            {"ip": "10.0.0.1", "role": "", "ports": []},
        ]
        assert _pick_gateway(group)["ip"] == "10.0.0.1"

    def test_non_gateway_suffix_falls_through_to_first(self):
        """When no role and no .1/.2/.254 suffix, lowest priority wins (first in iteration)."""
        # Both .10 and .20 get the same suffix_priority (len(order)=5), so min()
        # returns the first one in iteration order.
        group = [
            {"ip": "10.0.0.10", "role": "", "ports": ["22/tcp"]},
            {"ip": "10.0.0.20", "role": "", "ports": ["22/tcp", "80/tcp", "443/tcp"]},
        ]
        assert _pick_gateway(group)["ip"] == "10.0.0.10"


# ── infer_links_smart ────────────────────────────────────────────────

class TestInferLinksSmart:
    def test_hub_and_spoke_within_subnet(self):
        """All hosts in a subnet connect to the gateway (hub)."""
        hosts = [
            {"id": "h-gw", "ip": "10.0.0.1", "hostname": "gw",
             "role": "router", "tags": [], "ports": []},
            {"id": "h-1", "ip": "10.0.0.10", "hostname": "a",
             "role": "", "tags": [], "ports": []},
            {"id": "h-2", "ip": "10.0.0.20", "hostname": "b",
             "role": "", "tags": [], "ports": []},
        ]
        links = infer_links_smart(hosts)
        sources_targets = {(l.source_ip, l.target_ip) for l in links}
        # gw should be hub for both a and b (either direction is fine)
        assert (("10.0.0.1", "10.0.0.10") in sources_targets
                or ("10.0.0.10", "10.0.0.1") in sources_targets)
        assert (("10.0.0.1", "10.0.0.20") in sources_targets
                or ("10.0.0.20", "10.0.0.1") in sources_targets)

    def test_manual_gateway_overrides_heuristic(self):
        """When manual_gateway_by_subnet is provided, the named host becomes hub."""
        hosts = [
            {"id": "h-rt", "ip": "10.0.0.1", "hostname": "rt-with-low-ip",
             "role": "", "tags": [], "ports": []},
            {"id": "h-vpn", "ip": "10.0.0.50", "hostname": "VPN",
             "role": "network_device", "tags": [], "ports": []},
            {"id": "h-1", "ip": "10.0.0.10", "hostname": "a",
             "role": "", "tags": [], "ports": []},
        ]
        manual = {"10.0.0.0/24": "10.0.0.50"}
        links = infer_links_smart(hosts, manual)
        # VPN should be hub, not the .1
        non_vpn_to_a = any(
            (l.source_ip == "10.0.0.1" and l.target_ip == "10.0.0.10")
            for l in links
        )
        vpn_to_a = any(
            (l.source_ip == "10.0.0.50" and l.target_ip == "10.0.0.10")
            for l in links
        )
        assert vpn_to_a and not non_vpn_to_a

    def test_no_links_for_singleton_subnet(self):
        """A subnet with one host gets no hub-and-spoke edges."""
        hosts = [
            {"id": "h", "ip": "10.0.0.5", "hostname": "lone",
             "role": "", "tags": [], "ports": []},
        ]
        assert infer_links_smart(hosts) == []

    def test_isolated_subnet_skips_inter_subnet_only(self):
        """isolated_subnets blocks gateway↔gateway between subnets, not hub-and-spoke within."""
        hosts = [
            # Subnet A — normal, gw at .1
            {"id": "h-gw-a", "ip": "10.0.0.1", "hostname": "gw-a",
             "role": "router", "tags": [], "ports": [], "subnet": "10.0.0.0/24"},
            {"id": "h-1", "ip": "10.0.0.10", "hostname": "a",
             "role": "", "tags": [], "ports": [], "subnet": "10.0.0.0/24"},
            # Subnet B — isolated (reachable only via pivot)
            {"id": "h-gw-b", "ip": "172.16.0.1", "hostname": "gw-b",
             "role": "router", "tags": [], "ports": [], "subnet": "172.16.0.0/24"},
            {"id": "h-2", "ip": "172.16.0.10", "hostname": "b",
             "role": "", "tags": [], "ports": [], "subnet": "172.16.0.0/24"},
        ]
        links = infer_links_smart(hosts, isolated_subnets={"172.16.0.0/24"})
        pairs = {tuple(sorted([l.source_ip, l.target_ip])) for l in links}
        # Intra-subnet hub-and-spoke still happens in both subnets
        assert ("10.0.0.1", "10.0.0.10") in pairs
        assert ("172.16.0.1", "172.16.0.10") in pairs
        # But the inter-subnet gw↔gw link is SUPPRESSED for isolated
        assert ("10.0.0.1", "172.16.0.1") not in pairs
