"""Consolidated tests for test_topology_infer (merged variant files)."""

# ════════ from test_topology_infer_extra.py ════════
import pytest
from unittest.mock import patch, MagicMock

from app.routers.topology._infer import (
    _get_subnet,
    infer_links,
    _is_gateway,
    _pick_gateway,
    _build_host_by_ip,
    _get_subnet_for_ip,
    _group_hosts_by_subnet,
    _gw_reason_str,
    _infer_intra_subnet,
    _infer_inter_subnet,
    infer_links_smart,
    _add_inferred_link,
    TopologyLinkDiff,
)


class TestGetSubnet_extra:
    def test_normal(self):
        assert _get_subnet("10.0.0.5") == "10.0.0.0/24"

    def test_short(self):
        assert _get_subnet("1.2.3") == "0.0.0.0/24"


class TestInferLinks_extra:
    def test_empty(self):
        assert infer_links([]) == []

    def test_same_subnet(self):
        hosts = [
            {"ip": "10.0.0.1"},
            {"ip": "10.0.0.2"},
        ]
        links = infer_links(hosts)
        assert len(links) >= 1

    def test_different_subnets(self):
        hosts = [
            {"ip": "10.0.0.1"},
            {"ip": "192.168.1.1"},
        ]
        links = infer_links(hosts)
        assert len(links) == 0


class TestIsGateway_extra:
    def test_role_router(self):
        assert _is_gateway({"role": "router", "tags": [], "os": ""}) is True

    def test_role_firewall(self):
        assert _is_gateway({"role": "firewall", "tags": [], "os": ""}) is True

    def test_tag(self):
        assert _is_gateway({"role": "", "tags": ["gateway"], "os": ""}) is True

    def test_router_os(self):
        assert _is_gateway({"role": "", "tags": [], "os": "cisco ios"}) is True

    def test_not_gateway(self):
        assert _is_gateway({"role": "server", "tags": [], "os": "linux"}) is False


class TestPickGateway:
    def test_explicit_router(self):
        hosts = [
            {"ip": "10.0.0.1", "role": "router", "tags": [], "os": ""},
            {"ip": "10.0.0.2", "role": "server", "tags": [], "os": ""},
        ]
        gw = _pick_gateway(hosts)
        assert gw["ip"] == "10.0.0.1"

    def test_suffix_priority_1(self):
        hosts = [
            {"ip": "10.0.0.55", "ports": [], "tags": [], "role": "", "os": ""},
            {"ip": "10.0.0.1", "ports": [], "tags": [], "role": "", "os": ""},
        ]
        gw = _pick_gateway(hosts)
        assert gw["ip"] == "10.0.0.1"

    def test_suffix_priority_254(self):
        hosts = [
            {"ip": "10.0.0.55", "ports": [], "tags": [], "role": "", "os": ""},
            {"ip": "10.0.0.254", "ports": [], "tags": [], "role": "", "os": ""},
        ]
        gw = _pick_gateway(hosts)
        assert gw["ip"] == "10.0.0.254"

    def test_suffix_priority_equal(self):
        hosts = [
            {"ip": "10.0.0.100", "ports": ["80/tcp"], "tags": [], "role": "", "os": ""},
            {"ip": "10.0.0.200", "ports": ["80/tcp", "443/tcp", "22/tcp"], "tags": [], "role": "", "os": ""},
        ]
        gw = _pick_gateway(hosts)
        assert gw["ip"] == "10.0.0.100"

    def test_suffix_priority_diff(self):
        hosts = [
            {"ip": "10.0.0.100", "ports": [], "tags": [], "role": "", "os": ""},
            {"ip": "10.0.0.1", "ports": [], "tags": [], "role": "", "os": ""},
        ]
        gw = _pick_gateway(hosts)
        assert gw["ip"] == "10.0.0.1"

    def test_fallback_ip_sort(self):
        hosts = [
            {"ip": "10.0.0.10", "ports": [], "tags": [], "role": "", "os": ""},
            {"ip": "10.0.0.50", "ports": [], "tags": [], "role": "", "os": ""},
        ]
        gw = _pick_gateway(hosts)
        assert gw["ip"] == "10.0.0.10"


class TestBuildHostByIp_extra:
    def test_basic(self):
        hosts = [
            {"ip": "10.0.0.1", "ips": ["10.0.0.100"]},
            {"ip": "10.0.0.2", "ips": []},
        ]
        r = _build_host_by_ip(hosts)
        assert "10.0.0.1" in r
        assert "10.0.0.100" in r
        assert "10.0.0.2" in r

    def test_empty_ip(self):
        hosts = [{"ip": "", "ips": []}]
        r = _build_host_by_ip(hosts)
        assert len(r) == 0


class TestGetSubnetForIp:
    def test_primary(self):
        r = _get_subnet_for_ip("10.0.0.1", "10.0.0.1", {"subnet": "10.0.0.0/24"})
        assert r == "10.0.0.0/24"

    def test_secondary(self):
        r = _get_subnet_for_ip("10.0.1.5", "10.0.0.1", {"subnet": "10.0.0.0/24"})
        assert r == "10.0.1.0/24"

    def test_primary_no_subnet(self):
        r = _get_subnet_for_ip("10.0.0.1", "10.0.0.1", {"subnet": ""})
        assert r == "10.0.0.0/24"


class TestGroupHostsBySubnet_extra:
    def test_basic(self):
        hosts = [
            {"id": "h1", "ip": "10.0.0.1", "ips": [], "subnet": "10.0.0.0/24"},
            {"id": "h2", "ip": "10.0.0.2", "ips": [], "subnet": "10.0.0.0/24"},
            {"id": "h3", "ip": "10.0.1.1", "ips": [], "subnet": "10.0.1.0/24"},
        ]
        r = _group_hosts_by_subnet(hosts)
        assert "10.0.0.0/24" in r
        assert "10.0.1.0/24" in r
        assert len(r["10.0.0.0/24"]) == 2

    def test_no_ip(self):
        hosts = [{"id": "h1", "ip": "", "ips": []}]
        r = _group_hosts_by_subnet(hosts)
        assert len(r) == 0

    def test_extra_ips(self):
        hosts = [
            {"id": "h1", "ip": "10.0.0.1", "ips": ["10.0.1.1"], "subnet": ""},
        ]
        r = _group_hosts_by_subnet(hosts)
        assert "10.0.0.0/24" in r
        assert "10.0.1.0/24" in r


class TestGwReasonStr_extra:
    def test_manual(self):
        gw = {"hostname": "gw1", "role": "", "tags": [], "os": "", "ports": []}
        r = _gw_reason_str(gw, "10.0.0.1", "manual")
        assert "manual scope gateway" in r

    def test_gateway_role(self):
        gw = {"hostname": "gw1", "role": "router", "tags": [], "os": "", "ports": []}
        r = _gw_reason_str(gw, "10.0.0.1", None)
        assert "gateway role/tag" in r

    def test_common_suffix(self):
        gw = {"hostname": "gw1", "role": "", "tags": [], "os": "", "ports": []}
        r = _gw_reason_str(gw, "10.0.0.1", None)
        assert "common gateway IP suffix" in r

    def test_ports_heuristic(self):
        gw = {"hostname": "gw1", "role": "", "tags": [], "os": "", "ports": ["80/tcp", "22/tcp"]}
        r = _gw_reason_str(gw, "10.0.0.55", None)
        assert "most open ports" in r


class TestInferIntraSubnet:
    def test_basic(self):
        subnet_hosts = {
            "10.0.0.0/24": [
                {"ip": "10.0.0.1", "id": "h1", "role": "router", "tags": [], "os": "", "ports": []},
                {"ip": "10.0.0.2", "id": "h2", "role": "server", "tags": [], "os": "", "ports": []},
            ]
        }
        host_by_ip = {
            "10.0.0.1": subnet_hosts["10.0.0.0/24"][0],
            "10.0.0.2": subnet_hosts["10.0.0.0/24"][1],
        }
        links = []
        seen = set()
        r = _infer_intra_subnet(subnet_hosts, seen, links, {}, host_by_ip)
        assert "10.0.0.0/24" in r
        assert len(links) == 1

    def test_single_host(self):
        subnet_hosts = {
            "10.0.0.0/24": [{"ip": "10.0.0.1", "id": "h1"}]
        }
        links = []
        seen = set()
        r = _infer_intra_subnet(subnet_hosts, seen, links, {}, {})
        assert len(links) == 0

    def test_manual_gateway(self):
        subnet_hosts = {
            "10.0.0.0/24": [
                {"ip": "10.0.0.1", "id": "h1", "role": "", "tags": [], "os": "", "ports": []},
                {"ip": "10.0.0.2", "id": "h2", "role": "", "tags": [], "os": "", "ports": []},
            ]
        }
        host_by_ip = {
            "10.0.0.1": subnet_hosts["10.0.0.0/24"][0],
            "10.0.0.2": subnet_hosts["10.0.0.0/24"][1],
            "10.0.0.254": {"ip": "10.0.0.254", "id": "gw"},
        }
        links = []
        seen = set()
        r = _infer_intra_subnet(
            subnet_hosts, seen, links, {"10.0.0.0/24": "10.0.0.254"}, host_by_ip
        )
        assert "10.0.0.0/24" in r
        assert r["10.0.0.0/24"] == "10.0.0.254"


class TestInferInterSubnet:
    def test_basic(self):
        subnet_gw = {"10.0.0.0/24": "10.0.0.1", "10.0.1.0/24": "10.0.1.1"}
        links = []
        seen = set()
        _infer_inter_subnet(subnet_gw, set(), seen, links)
        assert len(links) == 1

    def test_isolated(self):
        subnet_gw = {"10.0.0.0/24": "10.0.0.1", "10.0.1.0/24": "10.0.1.1"}
        links = []
        seen = set()
        _infer_inter_subnet(subnet_gw, {"10.0.1.0/24"}, seen, links)
        assert len(links) == 0


class TestInferLinksSmart_extra:
    def test_empty(self):
        assert infer_links_smart([]) == []

    def test_basic(self):
        hosts = [
            {"id": "h1", "ip": "10.0.0.1", "ips": [], "role": "router", "tags": [], "os": "", "ports": []},
            {"id": "h2", "ip": "10.0.0.2", "ips": [], "role": "server", "tags": [], "os": "", "ports": []},
            {"id": "h3", "ip": "10.0.1.1", "ips": [], "role": "router", "tags": [], "os": "", "ports": []},
            {"id": "h4", "ip": "10.0.1.2", "ips": [], "role": "server", "tags": [], "os": "", "ports": []},
        ]
        links = infer_links_smart(hosts)
        assert len(links) >= 2

    def test_with_isolated(self):
        hosts = [
            {"id": "h1", "ip": "10.0.0.1", "ips": [], "role": "", "tags": [], "os": "", "ports": []},
            {"id": "h2", "ip": "10.0.0.2", "ips": [], "role": "", "tags": [], "os": "", "ports": []},
            {"id": "h3", "ip": "10.0.1.1", "ips": [], "role": "", "tags": [], "os": "", "ports": []},
        ]
        links = infer_links_smart(hosts, isolated_subnets={"10.0.1.0/24"})
        intra = [l for l in links if l.link_type == "same_subnet"]
        inter = [l for l in links if l.link_type == "lan"]
        assert len(intra) >= 1
        assert len(inter) == 0


class TestAddInferredLink_extra:
    def test_basic(self):
        links = []
        seen = set()
        _add_inferred_link("10.0.0.1", "10.0.0.2", seen, links)
        assert len(links) == 1

    def test_duplicate(self):
        links = []
        seen = set()
        _add_inferred_link("10.0.0.1", "10.0.0.2", seen, links)
        _add_inferred_link("10.0.0.1", "10.0.0.2", seen, links)
        assert len(links) == 1

    def test_same_ip(self):
        links = []
        seen = set()
        _add_inferred_link("10.0.0.1", "10.0.0.1", seen, links)
        assert len(links) == 0

    def test_custom_params(self):
        links = []
        seen = set()
        _add_inferred_link("a", "b", seen, links, link_type="lan", confidence=0.7, label="test", reason="r")
        assert links[0].link_type == "lan"
        assert links[0].confidence == 0.7


# ════════ from test_topology_infer_final.py ════════
import pytest
import ipaddress
from unittest.mock import MagicMock

from app.routers.topology._infer import (
    _get_subnet,
    infer_links,
    _is_gateway,
    _scope_region_colors,
    _host_matches_gateway_ip,
    _region_center,
    _midpoint_in_overlap,
    _place_between_regions,
    _place_on_region_edge,
    _host_scope_memberships,
    _pick_gateway,
    _add_inferred_link,
    _build_host_by_ip,
    _get_subnet_for_ip,
    _group_hosts_by_subnet,
    _gw_reason_str,
    infer_links_smart,
    TopologyLinkDiff,
)


class TestGetSubnet_final:
    def test_ipv4(self):
        assert _get_subnet("192.168.1.5") == "192.168.1.0/24"

    def test_non_ipv4(self):
        assert _get_subnet("invalid") == "0.0.0.0/24"


class TestInferLinks_final:
    def test_two_hosts_same_subnet(self):
        hosts = [{"ip": "10.0.0.1"}, {"ip": "10.0.0.2"}]
        links = infer_links(hosts)
        assert len(links) == 1
        assert links[0].link_type == "same_subnet"

    def test_different_subnets(self):
        hosts = [{"ip": "10.0.0.1"}, {"ip": "192.168.1.1"}]
        links = infer_links(hosts)
        assert len(links) == 0

    def test_single_host(self):
        links = infer_links([{"ip": "10.0.0.1"}])
        assert len(links) == 0

    def test_no_ip(self):
        links = infer_links([{}])
        assert len(links) == 0


class TestIsGateway_final:
    def test_role_match(self):
        assert _is_gateway({"role": "router"}) is True

    def test_tag_match(self):
        assert _is_gateway({"tags": ["firewall"]}) is True

    def test_os_match(self):
        assert _is_gateway({"os": "Cisco IOS"}) is True

    def test_no_match(self):
        assert _is_gateway({"role": "server", "tags": [], "os": "Windows"}) is False


class TestScopeRegionColors:
    def test_via_host(self):
        c, f = _scope_region_colors("10.0.0.0/24", True, via_host_id="h1")
        assert c == "#f09a3a"

    def test_in_scope(self):
        c, f = _scope_region_colors("10.0.0.0/24", True)
        assert isinstance(c, str)

    def test_out_scope(self):
        c, f = _scope_region_colors("10.0.0.0/24", False)
        assert c == "#cc2233"


class TestHostMatchesGatewayIp:
    def test_empty(self):
        assert _host_matches_gateway_ip({}, "") is False

    def test_primary_ip(self):
        assert _host_matches_gateway_ip({"ip": "10.0.0.1"}, "10.0.0.1") is True

    def test_extra_ip(self):
        assert _host_matches_gateway_ip({"ip": "10.0.0.1", "ips": ["10.0.0.2"]}, "10.0.0.2") is True

    def test_no_match(self):
        assert _host_matches_gateway_ip({"ip": "10.0.0.1"}, "10.0.0.2") is False


class TestRegionCenter:
    def test_basic(self):
        x, y = _region_center({"x": 10, "y": 20, "w": 100, "h": 60})
        assert x == 60.0
        assert y == 50.0

    def test_zero(self):
        x, y = _region_center({})
        assert x == 0.0
        assert y == 0.0


class TestMidpointInOverlap:
    def test_overlap(self):
        mid = _midpoint_in_overlap(0, 100, 50, 100)
        assert mid == 75.0

    def test_no_overlap(self):
        mid = _midpoint_in_overlap(0, 100, 200, 100)
        assert mid > 0


class TestPlaceBetweenRegions:
    def test_a_left_of_b(self):
        ra = {"x": 0, "y": 0, "w": 100, "h": 100}
        rb = {"x": 200, "y": 0, "w": 100, "h": 100}
        x, y = _place_between_regions(ra, rb)
        assert x > 100
        assert x < 200

    def test_a_above_b(self):
        ra = {"x": 0, "y": 0, "w": 100, "h": 100}
        rb = {"x": 0, "y": 200, "w": 100, "h": 100}
        x, y = _place_between_regions(ra, rb)
        assert y > 100
        assert y < 200


class TestPlaceOnRegionEdge:
    def test_left(self):
        x, y = _place_on_region_edge({"x": 100, "y": 100, "w": 50, "h": 50}, "left")
        assert x < 100

    def test_right(self):
        x, y = _place_on_region_edge({"x": 100, "y": 100, "w": 50, "h": 50}, "right")
        assert x > 150

    def test_top(self):
        x, y = _place_on_region_edge({"x": 100, "y": 100, "w": 50, "h": 50}, "top")
        assert y < 100

    def test_bottom(self):
        x, y = _place_on_region_edge({"x": 100, "y": 100, "w": 50, "h": 50}, "bottom")
        assert y > 150


class TestHostScopeMemberships:
    def test_matching(self):
        net_obj = ipaddress.ip_network("10.0.0.0/24")
        result = _host_scope_memberships(
            {"ip": "10.0.0.1", "ips": []},
            [{"net_obj": net_obj, "cidr": "10.0.0.0/24"}],
        )
        assert "10.0.0.0/24" in result

    def test_no_match(self):
        net_obj = ipaddress.ip_network("10.0.0.0/24")
        result = _host_scope_memberships(
            {"ip": "192.168.1.1", "ips": []},
            [{"net_obj": net_obj, "cidr": "10.0.0.0/24"}],
        )
        assert len(result) == 0


class TestAddInferredLink_final:
    def test_adds(self):
        links = []
        seen = set()
        _add_inferred_link("10.0.0.1", "10.0.0.2", seen, links)
        assert len(links) == 1

    def test_dedup(self):
        links = []
        seen = set()
        _add_inferred_link("10.0.0.1", "10.0.0.2", seen, links)
        _add_inferred_link("10.0.0.2", "10.0.0.1", seen, links)
        assert len(links) == 1

    def test_self_link(self):
        links = []
        seen = set()
        _add_inferred_link("10.0.0.1", "10.0.0.1", seen, links)
        assert len(links) == 0


class TestBuildHostByIp_final:
    def test_basic(self):
        result = _build_host_by_ip([{"ip": "10.0.0.1", "id": "h1"}, {"ip": "10.0.0.2", "ips": ["10.0.0.3"], "id": "h2"}])
        assert "10.0.0.1" in result
        assert "10.0.0.2" in result
        assert "10.0.0.3" in result


class TestGroupHostsBySubnet_final:
    def test_basic(self):
        hosts = [{"ip": "10.0.0.1", "id": "h1"}, {"ip": "10.0.0.2", "id": "h2"}]
        result = _group_hosts_by_subnet(hosts)
        assert "10.0.0.0/24" in result
        assert len(result["10.0.0.0/24"]) == 2

    def test_empty(self):
        assert _group_hosts_by_subnet([]) == {}


class TestGwReasonStr_final:
    def test_manual_gw(self):
        result = _gw_reason_str({"hostname": "gw"}, "10.0.0.1", "manual")
        assert "manual" in result

    def test_gateway_role(self):
        result = _gw_reason_str({"hostname": "fw", "role": "firewall", "tags": [], "ip": "10.0.0.1"}, "10.0.0.1", None)
        assert "gateway" in result.lower() or "firewall" in result.lower()

    def test_suffix(self):
        result = _gw_reason_str({"hostname": "gw", "role": "", "tags": [], "ip": "10.0.0.1", "ports": []}, "10.0.0.1", None)
        assert "." in result or "port" in result

    def test_most_ports(self):
        result = _gw_reason_str({"hostname": "srv", "role": "", "tags": [], "ip": "10.0.0.50", "ports": ["22/tcp", "80/tcp"]}, "10.0.0.50", None)
        assert "port" in result or "hub" in result


class TestInferLinksSmart_final:
    def test_empty(self):
        assert infer_links_smart([]) == []

    def test_basic(self):
        hosts = [
            {"id": "h1", "ip": "10.0.0.1", "hostname": "", "os": "", "status": "up", "role": "router", "is_attacker": False, "ports": [], "services": [], "tags": []},
            {"id": "h2", "ip": "10.0.0.2", "hostname": "", "os": "", "status": "up", "role": "", "is_attacker": False, "ports": [], "services": [], "tags": []},
        ]
        links = infer_links_smart(hosts)
        assert len(links) >= 1
