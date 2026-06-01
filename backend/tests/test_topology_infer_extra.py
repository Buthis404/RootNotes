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


class TestGetSubnet:
    def test_normal(self):
        assert _get_subnet("10.0.0.5") == "10.0.0.0/24"

    def test_short(self):
        assert _get_subnet("1.2.3") == "0.0.0.0/24"


class TestInferLinks:
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


class TestIsGateway:
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


class TestBuildHostByIp:
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


class TestGroupHostsBySubnet:
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


class TestGwReasonStr:
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


class TestInferLinksSmart:
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


class TestAddInferredLink:
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
