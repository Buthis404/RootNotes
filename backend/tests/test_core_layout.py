"""Unit tests for app.core.layout — network topology layout engine."""
import math
from unittest.mock import patch

from app.core.layout import (
    ATTACKER_OFFSET,
    CANVAS_LEFT,
    CANVAS_TOP,
    CLUSTER_H_GAP,
    CLUSTER_PAD_X,
    CLUSTER_PAD_Y,
    CLUSTER_V_GAP,
    NODE_H,
    NODE_W,
    NODES_PER_ROW,
    TIER_GAP,
    _build_subnet_adjacency,
    _barycenter_reorder,
    _cluster_dims,
    _collect_manual_positions,
    _compute_cluster_origins,
    _count_private_ips,
    _device_tier,
    _host_sort_key,
    _host_subnet,
    _place_attackers,
    _place_cluster_nodes,
    _subnet_depth,
    compute_layout,
)


class TestDeviceTier:
    def test_attacker_by_flag(self):
        assert _device_tier({"is_attacker": True}) == -1

    def test_attacker_by_role(self):
        assert _device_tier({"role": "Attacker"}) == -1

    def test_router(self):
        assert _device_tier({"device_type": "router"}) == 0

    def test_firewall(self):
        assert _device_tier({"device_type": "firewall"}) == 0

    def test_switch(self):
        assert _device_tier({"type": "switch"}) == 0

    def test_gateway_tag(self):
        assert _device_tier({"tags": ["gateway"]}) == 0

    def test_perimeter_tag(self):
        assert _device_tier({"tags": ["perimeter", "linux"]}) == 0

    def test_gateway_os_cisco(self):
        assert _device_tier({"os": "Cisco IOS 15"}) == 0

    def test_gateway_os_pfsense(self):
        assert _device_tier({"os": "pfSense 2.5"}) == 0

    def test_server_by_port(self):
        assert _device_tier({"ports": ["80/tcp"]}) == 1

    def test_server_by_port_443(self):
        assert _device_tier({"ports": ["443/tcp"]}) == 1

    def test_server_by_port_3306(self):
        assert _device_tier({"ports": ["3306/tcp"]}) == 1

    def test_endpoint_by_os(self):
        assert _device_tier({"os": "Windows 10 Pro"}) == 2

    def test_endpoint_macos(self):
        assert _device_tier({"os": "macOS Ventura"}) == 2

    def test_default_server(self):
        assert _device_tier({}) == 1

    def test_empty_dict(self):
        assert _device_tier({}) == 1

    def test_port_with_slash(self):
        assert _device_tier({"ports": ["22/tcp", "80/tcp"]}) == 1

    def test_port_without_slash(self):
        assert _device_tier({"ports": ["22"]}) == 1

    def test_invalid_port_ignored(self):
        assert _device_tier({"ports": ["abc"]}) == 1

    def test_non_gateway_os(self):
        assert _device_tier({"os": "Ubuntu 22.04"}) == 1

    def test_endpoint_os_windows_11(self):
        assert _device_tier({"os": "Windows 11 Enterprise"}) == 2

    def test_case_insensitive_device_type(self):
        assert _device_tier({"device_type": "Router"}) == 0

    def test_case_insensitive_tag(self):
        assert _device_tier({"tags": ["GATEWAY"]}) == 0

    def test_mixed_tags_server_port(self):
        assert _device_tier({"tags": ["web"], "ports": ["443/tcp"]}) == 1


class TestHostSubnet:
    def test_explicit_subnet(self):
        result = _host_subnet({"subnet": "10.10.20.0/24"})
        assert result == "10.10.20.0/24"

    def test_explicit_larger_subnet(self):
        result = _host_subnet({"subnet": "10.10.20.0/16"})
        assert result == "10.10.0.0/24"

    def test_from_ip(self):
        result = _host_subnet({"ip": "192.168.1.55"})
        assert result == "192.168.1.0/24"

    def test_empty_ip(self):
        result = _host_subnet({})
        assert result == "0.0.0.0/24"

    def test_none_ip(self):
        result = _host_subnet({"ip": None})
        assert result == "0.0.0.0/24"

    def test_empty_string_ip(self):
        result = _host_subnet({"ip": ""})
        assert result == "0.0.0.0/24"

    def test_invalid_subnet_ignored(self):
        result = _host_subnet({"subnet": "not-a-subnet", "ip": "10.0.0.1"})
        assert result == "10.0.0.0/24"

    def test_ipv6_like(self):
        result = _host_subnet({"ip": "::1"})
        assert result == "0.0.0.0/24"


class TestCountPrivateIps:
    def test_empty(self):
        assert _count_private_ips([]) == 0

    def test_private_ips(self):
        hosts = [{"ip": "10.0.0.1"}, {"ip": "192.168.1.1"}, {"ip": "172.16.0.1"}]
        assert _count_private_ips(hosts) == 3

    def test_public_ips(self):
        hosts = [{"ip": "8.8.8.8"}, {"ip": "1.1.1.1"}]
        assert _count_private_ips(hosts) == 0

    def test_mixed(self):
        hosts = [{"ip": "10.0.0.1"}, {"ip": "8.8.8.8"}]
        assert _count_private_ips(hosts) == 1

    def test_none_ip(self):
        assert _count_private_ips([{"ip": None}]) == 0

    def test_empty_ip(self):
        assert _count_private_ips([{"ip": ""}]) == 0


class TestSubnetDepth:
    def test_internet_tag(self):
        hosts = [{"tags": ["internet"]}]
        assert _subnet_depth(hosts) == 0

    def test_external_tag(self):
        hosts = [{"tags": ["external"]}]
        assert _subnet_depth(hosts) == 0

    def test_public_tag(self):
        hosts = [{"tags": ["public"]}]
        assert _subnet_depth(hosts) == 0

    def test_dmz_tag(self):
        hosts = [{"tags": ["dmz"]}]
        assert _subnet_depth(hosts) == 1

    def test_perimeter_tag_depth(self):
        hosts = [{"tags": ["perimeter"]}]
        assert _subnet_depth(hosts) == 1

    def test_screened_tag(self):
        hosts = [{"tags": ["screened"]}]
        assert _subnet_depth(hosts) == 1

    def test_ad_tag(self):
        hosts = [{"tags": ["ad"]}]
        assert _subnet_depth(hosts) == 3

    def test_ot_tag(self):
        hosts = [{"tags": ["ot"]}]
        assert _subnet_depth(hosts) == 3

    def test_isolated_tag(self):
        hosts = [{"tags": ["isolated"]}]
        assert _subnet_depth(hosts) == 3

    def test_internal_default(self):
        hosts = [{"ip": "10.0.0.1"}]
        assert _subnet_depth(hosts) == 2

    def test_empty_hosts(self):
        assert _subnet_depth([]) == 2

    def test_public_ip_no_private(self):
        hosts = [{"ip": "8.8.8.8"}]
        assert _subnet_depth(hosts) == 0

    def test_mixed_tags_priority(self):
        hosts = [{"tags": ["internet", "dmz"]}]
        assert _subnet_depth(hosts) == 0


class TestClusterDims:
    def test_empty(self):
        w, h = _cluster_dims({})
        assert w == 2 * CLUSTER_PAD_X
        assert h == 2 * CLUSTER_PAD_Y

    def test_single_tier_single_host(self):
        tiers = {0: [{"ip": "10.0.0.1"}]}
        w, h = _cluster_dims(tiers)
        assert w == NODE_W + 2 * CLUSTER_PAD_X
        assert h == NODE_H + 2 * CLUSTER_PAD_Y

    def test_single_tier_many_hosts(self):
        tiers = {0: [{"ip": f"10.0.0.{i}"} for i in range(6)]}
        w, h = _cluster_dims(tiers)
        assert w == NODES_PER_ROW * NODE_W + 2 * CLUSTER_PAD_X
        expected_rows = math.ceil(6 / NODES_PER_ROW)
        assert h == expected_rows * NODE_H + 2 * CLUSTER_PAD_Y

    def test_two_tiers(self):
        tiers = {0: [{"ip": "10.0.0.1"}], 1: [{"ip": "10.0.0.2"}]}
        w, h = _cluster_dims(tiers)
        assert h == 2 * NODE_H + TIER_GAP + 2 * CLUSTER_PAD_Y


class TestBuildSubnetAdjacency:
    def test_empty(self):
        ip_map, adj = _build_subnet_adjacency([], [])
        assert ip_map == {}
        assert len(adj) == 0

    def test_nodes_only(self):
        nodes = [{"ip": "10.0.0.1", "id": "n1"}]
        ip_map, adj = _build_subnet_adjacency(nodes, [])
        assert ip_map["10.0.0.1"] == "10.0.0.0/24"

    def test_cross_subnet_edge(self):
        nodes = [
            {"ip": "10.0.0.1", "id": "n1"},
            {"ip": "10.0.1.1", "id": "n2"},
        ]
        edges = [{"from": "n1", "to": "n2"}]
        ip_map, adj = _build_subnet_adjacency(nodes, edges)
        assert "10.0.0.0/24" in adj
        assert "10.0.1.0/24" in adj["10.0.0.0/24"]

    def test_same_subnet_edge_no_adjacency(self):
        nodes = [
            {"ip": "10.0.0.1", "id": "n1"},
            {"ip": "10.0.0.2", "id": "n2"},
        ]
        edges = [{"from": "n1", "to": "n2"}]
        ip_map, adj = _build_subnet_adjacency(nodes, edges)
        assert "10.0.0.0/24" not in adj or len(adj["10.0.0.0/24"]) == 0

    def test_edge_source_field(self):
        nodes = [
            {"ip": "10.0.0.1", "id": "n1"},
            {"ip": "10.0.1.1", "id": "n2"},
        ]
        edges = [{"source": "n1", "target": "n2"}]
        ip_map, adj = _build_subnet_adjacency(nodes, edges)
        assert "10.0.0.0/24" in adj


class TestBarycenterReorder:
    def test_empty_layers(self):
        layers = {}
        _barycenter_reorder(layers, [], [])
        assert layers == {}

    def test_single_layer_no_change(self):
        layers = {0: ["10.0.0.0/24", "10.0.1.0/24"]}
        _barycenter_reorder(layers, [], [])
        assert layers[0] == ["10.0.0.0/24", "10.0.1.0/24"]

    def test_reorder_by_connections(self):
        nodes = [
            {"ip": "10.0.0.1", "id": "n1"},
            {"ip": "10.0.1.1", "id": "n2"},
            {"ip": "10.0.2.1", "id": "n3"},
        ]
        edges = [{"from": "n1", "to": "n3"}]
        layers = {
            0: ["10.0.0.0/24"],
            1: ["10.0.1.0/24", "10.0.2.0/24"],
        }
        _barycenter_reorder(layers, nodes, edges)
        assert layers[1] == ["10.0.2.0/24", "10.0.1.0/24"]


class TestHostSortKey:
    def test_more_ports_first(self):
        h1 = {"ports": [1, 2, 3], "ip": "10.0.0.1"}
        h2 = {"ports": [1], "ip": "10.0.0.2"}
        assert _host_sort_key(h1) < _host_sort_key(h2)

    def test_same_ports_ip_sort(self):
        h1 = {"ports": [], "ip": "10.0.0.1"}
        h2 = {"ports": [], "ip": "10.0.0.2"}
        assert _host_sort_key(h1) < _host_sort_key(h2)

    def test_no_ports(self):
        h = {"ip": "10.0.0.1"}
        key = _host_sort_key(h)
        assert key[0] == 0


class TestCollectManualPositions:
    def test_empty(self):
        assert _collect_manual_positions([]) == {}

    def test_manual_position(self):
        nodes = [{"host_id": "h1", "manually_positioned": True, "x": 100, "y": 200}]
        result = _collect_manual_positions(nodes)
        assert result == {"h1": (100.0, 200.0)}

    def test_auto_positioned_ignored(self):
        nodes = [{"host_id": "h1", "manually_positioned": False, "x": 100, "y": 200}]
        assert _collect_manual_positions(nodes) == {}

    def test_ip_fallback_key(self):
        nodes = [{"ip": "10.0.0.1", "manually_positioned": True, "x": 50, "y": 75}]
        result = _collect_manual_positions(nodes)
        assert "10.0.0.1" in result


class TestComputeClusterOrigins:
    def test_single_layer_single_subnet(self):
        layers = {2: ["10.0.0.0/24"]}
        dims = {"10.0.0.0/24": (400, 300)}
        result = _compute_cluster_origins(layers, [2], dims)
        assert result["10.0.0.0/24"] == (CANVAS_LEFT, CANVAS_TOP)

    def test_two_layers(self):
        layers = {0: ["10.0.0.0/24"], 2: ["10.0.1.0/24"]}
        dims = {"10.0.0.0/24": (400, 300), "10.0.1.0/24": (400, 250)}
        result = _compute_cluster_origins(layers, [0, 2], dims)
        assert result["10.0.0.0/24"][1] == CANVAS_TOP
        assert result["10.0.1.0/24"][1] > CANVAS_TOP + 300

    def test_two_clusters_same_layer(self):
        layers = {2: ["10.0.0.0/24", "10.0.1.0/24"]}
        dims = {"10.0.0.0/24": (400, 300), "10.0.1.0/24": (400, 300)}
        result = _compute_cluster_origins(layers, [2], dims)
        assert result["10.0.1.0/24"][0] > result["10.0.0.0/24"][0] + 400


class TestPlaceClusterNodes:
    def test_single_host(self):
        tiers = {0: [{"id": "h1", "ip": "10.0.0.1"}]}
        result = _place_cluster_nodes(tiers, 0, 0, 400, {})
        assert len(result) == 1
        assert result[0]["auto_positioned"] is True
        assert "x" in result[0]
        assert "y" in result[0]

    def test_manual_override(self):
        tiers = {0: [{"id": "h1", "ip": "10.0.0.1"}]}
        manual = {"h1": (500, 600)}
        result = _place_cluster_nodes(tiers, 0, 0, 400, manual)
        assert result[0]["x"] == 500
        assert result[0]["y"] == 600
        assert result[0]["auto_positioned"] is False


class TestPlaceAttackers:
    def test_empty(self):
        assert _place_attackers([], {}, {}) == []

    def test_single_attacker(self):
        attackers = [{"id": "att1", "ip": "1.2.3.4", "is_attacker": True}]
        origins = {"10.0.0.0/24": (CANVAS_LEFT, CANVAS_TOP)}
        result = _place_attackers(attackers, origins, {})
        assert len(result) == 1
        assert result[0]["auto_positioned"] is True
        assert result[0]["y"] < CANVAS_TOP

    def test_manual_attacker_position(self):
        attackers = [{"id": "att1", "ip": "1.2.3.4"}]
        origins = {"10.0.0.0/24": (CANVAS_LEFT, CANVAS_TOP)}
        manual = {"att1": (300, 50)}
        result = _place_attackers(attackers, origins, manual)
        assert result[0]["x"] == 300
        assert result[0]["y"] == 50
        assert result[0]["auto_positioned"] is False

    def test_empty_origins(self):
        attackers = [{"id": "att1", "ip": "1.2.3.4"}]
        result = _place_attackers(attackers, {}, {})
        assert len(result) == 1


class TestComputeLayout:
    def test_empty_hosts(self):
        assert compute_layout([], []) == []

    def test_single_host(self):
        hosts = [{"id": "h1", "ip": "10.0.0.1"}]
        result = compute_layout(hosts, [])
        assert len(result) == 1
        assert "x" in result[0]
        assert "y" in result[0]

    def test_attacker_separated(self):
        hosts = [
            {"id": "att", "ip": "1.2.3.4", "is_attacker": True},
            {"id": "h1", "ip": "10.0.0.1"},
        ]
        result = compute_layout(hosts, [])
        assert len(result) == 2
        attacker = next(r for r in result if r.get("is_attacker"))
        regular = next(r for r in result if not r.get("is_attacker"))
        assert attacker["y"] < regular["y"]

    def test_manual_position_preserved(self):
        hosts = [{"id": "h1", "ip": "10.0.0.1"}]
        existing = [{"host_id": "h1", "manually_positioned": True, "x": 999, "y": 888}]
        result = compute_layout(hosts, existing, keep_manual=True)
        assert result[0]["x"] == 999
        assert result[0]["y"] == 888
        assert result[0]["auto_positioned"] is False

    def test_keep_manual_false(self):
        hosts = [{"id": "h1", "ip": "10.0.0.1"}]
        existing = [{"host_id": "h1", "manually_positioned": True, "x": 999, "y": 888}]
        result = compute_layout(hosts, existing, keep_manual=False)
        assert result[0]["auto_positioned"] is True

    def test_multiple_subnets(self):
        hosts = [
            {"id": "h1", "ip": "10.0.0.1"},
            {"id": "h2", "ip": "10.0.1.1"},
        ]
        result = compute_layout(hosts, [])
        assert len(result) == 2

    def test_hosts_preserve_extra_fields(self):
        hosts = [{"id": "h1", "ip": "10.0.0.1", "hostname": "server1"}]
        result = compute_layout(hosts, [])
        assert result[0]["hostname"] == "server1"

    def test_existing_edges_barycenter(self):
        hosts = [
            {"id": "h1", "ip": "10.0.0.1"},
            {"id": "h2", "ip": "10.0.1.1"},
        ]
        existing_nodes = [
            {"ip": "10.0.0.1", "id": "h1"},
            {"ip": "10.0.1.1", "id": "h2"},
        ]
        existing_edges = [{"from": "h1", "to": "h2"}]
        result = compute_layout(hosts, existing_nodes, existing_edges=existing_edges)
        assert len(result) == 2
