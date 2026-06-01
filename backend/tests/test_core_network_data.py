"""Unit tests for app.core.network_data — dict/ORM conversion and sync logic."""
from unittest.mock import MagicMock, patch

from app.core import network_data as nd


def _make_node_orm(**overrides):
    n = MagicMock()
    defaults = {
        "id": "n1",
        "host_id": None,
        "x": 0.0,
        "y": 0.0,
        "label": "",
        "ip": "10.0.0.1",
        "ips": [],
        "type": "host",
        "status": "unknown",
        "ports": [],
        "notes": "",
        "role": "",
        "os": "",
        "tags": [],
        "is_attacker": False,
        "manually_positioned": False,
        "auto_positioned": True,
        "updated_at": "",
        "version": 1,
        "extra_json": None,
    }
    defaults.update(overrides)
    for k, v in defaults.items():
        setattr(n, k, v)
    return n


def _make_edge_orm(**overrides):
    e = MagicMock()
    defaults = {
        "id": "e1",
        "from_node_id": "n1",
        "to_node_id": "n2",
        "style": "solid",
        "type": "network",
        "label": "",
        "confidence": 1.0,
        "source": "manual",
        "reason": "",
        "state": "manual",
        "verified": False,
        "is_manual": True,
        "manual_override": False,
        "updated_at": "",
        "version": 1,
        "extra_json": None,
    }
    defaults.update(overrides)
    for k, v in defaults.items():
        setattr(e, k, v)
    return e


def _make_region_orm(**overrides):
    r = MagicMock()
    defaults = {
        "id": "r1",
        "x": 0.0,
        "y": 0.0,
        "w": 200.0,
        "h": 100.0,
        "label": "",
        "note": "",
        "fill": "",
        "stroke": "",
        "zone_type": "",
        "updated_at": "",
        "version": 1,
        "extra_json": None,
    }
    defaults.update(overrides)
    for k, v in defaults.items():
        setattr(r, k, v)
    return r


class TestNodeToDict:
    def test_basic(self):
        n = _make_node_orm()
        d = nd._node_to_dict(n)
        assert d["id"] == "n1"
        assert d["ip"] == "10.0.0.1"
        assert d["type"] == "host"

    def test_extra_json_merged(self):
        n = _make_node_orm(extra_json={"custom_field": 42})
        d = nd._node_to_dict(n)
        assert d["custom_field"] == 42

    def test_none_extra_json(self):
        n = _make_node_orm(extra_json=None)
        d = nd._node_to_dict(n)
        assert "custom_field" not in d

    def test_ips_list(self):
        n = _make_node_orm(ips=["10.0.0.1", "10.0.0.2"])
        d = nd._node_to_dict(n)
        assert d["ips"] == ["10.0.0.1", "10.0.0.2"]

    def test_none_ips(self):
        n = _make_node_orm(ips=None)
        d = nd._node_to_dict(n)
        assert d["ips"] == []


class TestEdgeToDict:
    def test_basic(self):
        e = _make_edge_orm()
        d = nd._edge_to_dict(e)
        assert d["id"] == "e1"
        assert d["from"] == "n1"
        assert d["to"] == "n2"

    def test_transport_kind_derived(self):
        e = _make_edge_orm(type="ssh")
        d = nd._edge_to_dict(e)
        assert d["transport"] == "ssh"
        assert d["kind"] == "access"

    def test_extra_json_merged(self):
        e = _make_edge_orm(extra_json={"my_field": True})
        d = nd._edge_to_dict(e)
        assert d["my_field"] is True

    def test_extra_transport_not_overridden(self):
        e = _make_edge_orm(type="network", extra_json={"transport": "custom"})
        d = nd._edge_to_dict(e)
        assert d["transport"] == "custom"


class TestRegionToDict:
    def test_basic(self):
        r = _make_region_orm()
        d = nd._region_to_dict(r)
        assert d["id"] == "r1"
        assert d["w"] == 200.0

    def test_extra_json(self):
        r = _make_region_orm(extra_json={"color": "red"})
        d = nd._region_to_dict(r)
        assert d["color"] == "red"


class TestNodeMapping:
    def test_basic(self):
        d = {"id": "n1", "ip": "10.0.0.1"}
        result = nd._node_mapping("net1", "p1", d)
        assert result["id"] == "n1"
        assert result["network_id"] == "net1"
        assert result["pid"] == "p1"
        assert result["ip"] == "10.0.0.1"
        assert result["type"] == "host"

    def test_extra_fields_in_extra_json(self):
        d = {"id": "n1", "custom": "val"}
        result = nd._node_mapping("net1", "p1", d)
        assert result["extra_json"]["custom"] == "val"

    def test_defaults(self):
        d = {"id": "n1"}
        result = nd._node_mapping("net1", "p1", d)
        assert result["type"] == "host"
        assert result["status"] == "unknown"
        assert result["version"] == 1
        assert result["is_attacker"] is False


class TestEdgeMapping:
    def test_basic(self):
        d = {"id": "e1", "from": "n1", "to": "n2"}
        result = nd._edge_mapping("net1", "p1", d)
        assert result["from_node_id"] == "n1"
        assert result["to_node_id"] == "n2"

    def test_from_node_id_field(self):
        d = {"id": "e1", "from_node_id": "n1", "to_node_id": "n2"}
        result = nd._edge_mapping("net1", "p1", d)
        assert result["from_node_id"] == "n1"

    def test_confidence(self):
        d = {"id": "e1", "confidence": 0.85}
        result = nd._edge_mapping("net1", "p1", d)
        assert result["confidence"] == 0.85

    def test_confidence_none_default(self):
        d = {"id": "e1"}
        result = nd._edge_mapping("net1", "p1", d)
        assert result["confidence"] == 1.0


class TestRegionMapping:
    def test_basic(self):
        d = {"id": "r1", "x": 10, "y": 20}
        result = nd._region_mapping("net1", "p1", d)
        assert result["x"] == 10.0
        assert result["y"] == 20.0

    def test_default_wh(self):
        d = {"id": "r1"}
        result = nd._region_mapping("net1", "p1", d)
        assert result["w"] == 200.0
        assert result["h"] == 100.0


class TestSyncNodeStrictFields:
    def test_status_change(self):
        node = MagicMock(status="")
        host = MagicMock(status="up", role="", os="", is_attacker=False)
        assert nd._sync_node_strict_fields(node, host) is True
        assert node.status == "up"

    def test_no_change(self):
        node = MagicMock(status="up", role="", os="", is_attacker=False)
        host = MagicMock(status="up", role="", os="", is_attacker=False)
        assert nd._sync_node_strict_fields(node, host) is False

    def test_role_change(self):
        node = MagicMock(status="up", role="", os="", is_attacker=False)
        host = MagicMock(status="up", role="attacker", os="", is_attacker=False)
        assert nd._sync_node_strict_fields(node, host) is True
        assert node.role == "attacker"

    def test_os_change(self):
        node = MagicMock(status="", role="", os="Linux", is_attacker=False)
        host = MagicMock(status="", role="", os="Windows", is_attacker=False)
        assert nd._sync_node_strict_fields(node, host) is True
        assert node.os == "Windows"

    def test_is_attacker_change(self):
        node = MagicMock(status="", role="", os="", is_attacker=False)
        host = MagicMock(status="", role="", os="", is_attacker=True)
        assert nd._sync_node_strict_fields(node, host) is True
        assert node.is_attacker is True


class TestSyncNodeIpFields:
    def test_set_empty_node_ip(self):
        node = MagicMock(ip="", ips=[])
        host = MagicMock(ip="10.0.0.1", ips=None)
        assert nd._sync_node_ip_fields(node, host) is True
        assert node.ip == "10.0.0.1"

    def test_no_change(self):
        node = MagicMock(ip="10.0.0.1", ips=["10.0.0.1"])
        host = MagicMock(ip="10.0.0.1", ips=["10.0.0.1"])
        assert nd._sync_node_ip_fields(node, host) is False

    def test_host_ips_fallback_to_ip(self):
        node = MagicMock(ip="", ips=[])
        host = MagicMock(ip="10.0.0.1", ips=None)
        changed = nd._sync_node_ip_fields(node, host)
        assert changed is True

    def test_node_ips_not_overwritten_if_diverged(self):
        node = MagicMock(ip="10.0.0.1", ips=["10.0.0.1", "192.168.1.1"])
        host = MagicMock(ip="10.0.0.1", ips=["10.0.0.1"])
        assert nd._sync_node_ip_fields(node, host) is False


class TestSyncNodePorts:
    def test_update_ports(self):
        node = MagicMock(ports=[])
        host = MagicMock(ports=["22/tcp", "80/tcp"])
        assert nd._sync_node_ports(node, host) is True
        assert node.ports == ["22/tcp", "80/tcp"]

    def test_no_change(self):
        node = MagicMock(ports=["22/tcp"])
        host = MagicMock(ports=["22/tcp"])
        assert nd._sync_node_ports(node, host) is False

    def test_empty_host_ports_no_change(self):
        node = MagicMock(ports=["22/tcp"])
        host = MagicMock(ports=[])
        assert nd._sync_node_ports(node, host) is False

    def test_subset_update(self):
        node = MagicMock(ports=["22/tcp"])
        host = MagicMock(ports=["22/tcp", "80/tcp"])
        assert nd._sync_node_ports(node, host) is True


class TestSyncHostToNodes:
    def test_none_host(self):
        assert nd.sync_host_to_nodes(None, MagicMock()) == []

    def test_no_nodes(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = []
        host = MagicMock(id="h1", status="up", role="", os="", is_attacker=False, ip="10.0.0.1", ips=None, ports=[])
        assert nd.sync_host_to_nodes(host, db) == []

    def test_changed_node_returns_payload(self):
        node = MagicMock(
            id="n1", host_id="h1", network_id="net1",
            x=0, y=0, label="", ip="10.0.0.1", ips=[], type="host",
            status="", role="", os="", tags=[], notes="", ports=[],
            is_attacker=False, manually_positioned=False, auto_positioned=True,
            updated_at="", version=1, extra_json=None,
        )
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = [node]
        host = MagicMock(
            id="h1", status="up", role="", os="", is_attacker=False,
            ip="10.0.0.1", ips=["10.0.0.1"], ports=["22/tcp"],
        )
        result = nd.sync_host_to_nodes(host, db, ts="2026-01-01T00:00:00Z")
        assert len(result) == 1
        assert result[0]["network_id"] == "net1"
        assert node.version == 2
        assert node.updated_at == "2026-01-01T00:00:00Z"


class TestPopulateNodeRow:
    def test_basic(self):
        row = MagicMock()
        d = {"host_id": "h1", "ip": "10.0.0.1", "x": 100, "y": 200}
        nd._populate_node_row(row, d, {})
        assert row.host_id == "h1"
        assert row.ip == "10.0.0.1"
        assert row.x == 100.0
        assert row.y == 200.0

    def test_defaults(self):
        row = MagicMock()
        d = {"id": "n1"}
        nd._populate_node_row(row, d, {})
        assert row.type == "host"
        assert row.status == "unknown"
        assert row.version == 1

    def test_extra_stored(self):
        row = MagicMock()
        d = {"id": "n1", "custom": "val"}
        nd._populate_node_row(row, d, {"custom": "val"})
        assert row.extra_json == {"custom": "val"}


class TestNodeColsSet:
    def test_known_cols_not_in_extra(self):
        extra = {k: "val" for k in ["id", "ip", "label"]}
        d = {"id": "n1", "ip": "10.0.0.1", "custom": "yes"}
        result = {k: v for k, v in d.items() if k not in nd._NODE_COLS and k != "network_id" and k != "pid"}
        assert "custom" in result
        assert "id" not in result
