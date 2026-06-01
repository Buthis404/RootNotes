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


class TestGetSubnet:
    def test_ipv4(self):
        assert _get_subnet("192.168.1.5") == "192.168.1.0/24"

    def test_non_ipv4(self):
        assert _get_subnet("invalid") == "0.0.0.0/24"


class TestInferLinks:
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


class TestIsGateway:
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


class TestAddInferredLink:
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


class TestBuildHostByIp:
    def test_basic(self):
        result = _build_host_by_ip([{"ip": "10.0.0.1", "id": "h1"}, {"ip": "10.0.0.2", "ips": ["10.0.0.3"], "id": "h2"}])
        assert "10.0.0.1" in result
        assert "10.0.0.2" in result
        assert "10.0.0.3" in result


class TestGroupHostsBySubnet:
    def test_basic(self):
        hosts = [{"ip": "10.0.0.1", "id": "h1"}, {"ip": "10.0.0.2", "id": "h2"}]
        result = _group_hosts_by_subnet(hosts)
        assert "10.0.0.0/24" in result
        assert len(result["10.0.0.0/24"]) == 2

    def test_empty(self):
        assert _group_hosts_by_subnet([]) == {}


class TestGwReasonStr:
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


class TestInferLinksSmart:
    def test_empty(self):
        assert infer_links_smart([]) == []

    def test_basic(self):
        hosts = [
            {"id": "h1", "ip": "10.0.0.1", "hostname": "", "os": "", "status": "up", "role": "router", "is_attacker": False, "ports": [], "services": [], "tags": []},
            {"id": "h2", "ip": "10.0.0.2", "hostname": "", "os": "", "status": "up", "role": "", "is_attacker": False, "ports": [], "services": [], "tags": []},
        ]
        links = infer_links_smart(hosts)
        assert len(links) >= 1
