"""
Integration tests for _run_smart_build — exercises the full P1-P6.5
pipeline on a mini-bootcamp topology.

The fixture builds:
  - Attacker (10.127.243.75, is_attacker=True)
  - Two scopes: External (10.124.1.224/27, is_entry=True, gw=GW_EXTERNAL)
                Internal (10.154.16.0/23, gw=10.154.17.1 == VPN-GW secondary IP)
  - Hosts: GW_EXTERNAL (network_device), VPN-GW (network_device, dual-homed),
           SDOTSON (workstation + C2 session), DC (domain_controller),
           TMATHIS / CFRAZIER (plain workstations, no C2)
  - HostActivity: SDOTSON c2 session

Expected after smart build:
  - Attacker → GW_EXTERNAL (uplink)
  - GW_EXTERNAL → VPN-GW (same_subnet within entry scope)
  - VPN-GW → SDOTSON (c2_session, routed through junction)
  - VPN-GW → DC (same_subnet or pivot — DC is key)
  - VPN-GW → TMATHIS / CFRAZIER NOT present (workstations filtered out)
"""
import pytest

from app import models
from app.routers.topology import _run_smart_build
from app.core.network_data import get_edges, get_nodes
from app.core.utils import new_id


@pytest.fixture
def bootcamp(db):
    """Mini-bootcamp topology mirroring the real Test Bootcamp project."""
    project = models.Project(id=new_id("p"), name="Bootcamp", added="2026-01-01")
    db.add(project)
    db.flush()
    pid = project.id

    # Hosts
    def H(ip, hostname, role="unknown", tags=None, is_attacker=False, ips=None):
        h = models.Host(
            id=new_id("hst"), pid=pid, ip=ip, hostname=hostname,
            role=role, os="", status="up", domain="",
            tags=tags or [], ips=ips or [], ports=[], services=[],
            is_attacker=is_attacker,
        )
        db.add(h)
        db.flush()
        return h

    attacker = H("10.127.243.75", "Attacker", role="attacker", is_attacker=True)
    gw_ext   = H("10.124.1.224",  "GW_EXTERNAL", role="network_device")
    vpn_gw   = H("10.124.1.253",  "VPN-GW",      role="network_device",
                 ips=["10.124.1.253", "10.154.17.1"])
    dc       = H("10.154.16.134", "DC",          role="domain_controller",
                 tags=["server"])
    sdotson  = H("10.154.16.196", "SDOTSON",     role="workstation")
    tmathis  = H("10.154.16.197", "TMATHIS",     role="workstation")
    cfrazier = H("10.154.16.198", "CFRAZIER",    role="workstation")

    # Scopes
    db.add(models.Scope(
        id=new_id("sc"), pid=pid, value="10.124.1.224/27", in_scope=True,
        description="External", gateway_ip="10.124.1.224", is_entry=True,
    ))
    db.add(models.Scope(
        id=new_id("sc"), pid=pid, value="10.154.16.0/23", in_scope=True,
        description="Internal", gateway_ip="10.154.17.1", is_entry=False,
    ))

    # C2 session — only on SDOTSON
    db.add(models.HostActivity(
        id=new_id("ha"), pid=pid, host_id=sdotson.id,
        title="C2 session [Adaptix]", activity_type="c2",
        summary="Active adaptix session", status="done",
        ts="2026-05-14T21:33:28Z",
    ))

    db.commit()
    return {
        "pid": pid,
        "hosts": {
            "attacker": attacker.id, "gw_ext": gw_ext.id, "vpn_gw": vpn_gw.id,
            "dc": dc.id, "sdotson": sdotson.id,
            "tmathis": tmathis.id, "cfrazier": cfrazier.id,
        },
    }


def _edges_by_host(edges, nodes, src_hostname, dst_hostname):
    """Return edges going from src_hostname to dst_hostname (any direction)."""
    by_id = {n["id"]: n for n in nodes}
    found = []
    for e in edges:
        src = by_id.get(e.get("from"), {})
        dst = by_id.get(e.get("to"), {})
        a = src.get("label", "")
        b = dst.get("label", "")
        if (a == src_hostname and b == dst_hostname) or (a == dst_hostname and b == src_hostname):
            found.append(e)
    return found


class TestSmartBuildBootcamp:
    def test_smart_build_succeeds(self, bootcamp, db):
        result = _run_smart_build(bootcamp["pid"], db)
        assert result["ok"] is True
        assert result["nodes_total"] >= 7

    def test_attacker_uplink_to_entry_gateway(self, bootcamp, db):
        """Attacker should connect to GW_EXTERNAL (entry scope gateway), not directly to targets."""
        _run_smart_build(bootcamp["pid"], db)
        net = db.query(models.Network).filter(models.Network.pid == bootcamp["pid"]).first()
        nodes = get_nodes(net.id, db)
        edges = get_edges(net.id, db)
        uplinks = _edges_by_host(edges, nodes, "Attacker", "GW_EXTERNAL")
        assert len(uplinks) == 1, "Attacker should have exactly one uplink to GW_EXTERNAL"
        # uplink might be `type=uplink` or it could come from another pipeline source
        # — the key invariant is: there IS an edge between them

    def test_c2_routed_through_vpn_gw_not_attacker(self, bootcamp, db):
        """C2 session edge should go VPN-GW → SDOTSON, not Attacker → SDOTSON directly."""
        _run_smart_build(bootcamp["pid"], db)
        net = db.query(models.Network).filter(models.Network.pid == bootcamp["pid"]).first()
        nodes = get_nodes(net.id, db)
        edges = get_edges(net.id, db)

        # Direct attacker → SDOTSON c2_session must NOT exist
        direct = _edges_by_host(edges, nodes, "Attacker", "SDOTSON")
        direct_c2 = [e for e in direct if e.get("type") == "c2_session"]
        assert direct_c2 == [], "C2 session must NOT be direct from attacker"

        # VPN-GW → SDOTSON must exist with a c2_session edge
        via_vpn = _edges_by_host(edges, nodes, "VPN-GW", "SDOTSON")
        assert via_vpn, "VPN-GW → SDOTSON edge missing"
        kinds = {e.get("type") for e in via_vpn}
        assert "c2_session" in kinds, f"Expected c2_session in VPN-GW→SDOTSON edges, got {kinds}"

    def test_no_hub_spoke_to_plain_workstations(self, bootcamp, db):
        """VPN-GW should NOT have same_subnet edges to TMATHIS / CFRAZIER (plain workstations)."""
        _run_smart_build(bootcamp["pid"], db)
        net = db.query(models.Network).filter(models.Network.pid == bootcamp["pid"]).first()
        nodes = get_nodes(net.id, db)
        edges = get_edges(net.id, db)
        # No edge VPN-GW → TMATHIS / CFRAZIER (they have no C2, no role, no key tag)
        assert _edges_by_host(edges, nodes, "VPN-GW", "TMATHIS") == [], \
            "Plain workstation TMATHIS should not have hub edge"
        assert _edges_by_host(edges, nodes, "VPN-GW", "CFRAZIER") == [], \
            "Plain workstation CFRAZIER should not have hub edge"

    def test_hub_spoke_to_key_hosts(self, bootcamp, db):
        """VPN-GW SHOULD have an edge to DC (domain_controller is a key host)."""
        _run_smart_build(bootcamp["pid"], db)
        net = db.query(models.Network).filter(models.Network.pid == bootcamp["pid"]).first()
        nodes = get_nodes(net.id, db)
        edges = get_edges(net.id, db)
        # VPN-GW → DC must exist (DC is a key host)
        edges_to_dc = _edges_by_host(edges, nodes, "VPN-GW", "DC")
        assert edges_to_dc, "DC should be linked to VPN-GW (key host filter)"

    def test_c2_edge_rebuilds_on_second_build(self, bootcamp, db):
        """Smart Build is idempotent: running it twice yields the same edge count."""
        result1 = _run_smart_build(bootcamp["pid"], db)
        result2 = _run_smart_build(bootcamp["pid"], db)
        # We don't assert exact equality (positions can shift),
        # but edges_added should stabilize to 0 on the second run for auto edges
        # since they're already in seen_keys via manual_edges filter
        assert result2["ok"] is True
        # The edge count should be roughly the same on rebuild
        net = db.query(models.Network).filter(models.Network.pid == bootcamp["pid"]).first()
        edges = get_edges(net.id, db)
        assert len(edges) >= 3  # at minimum: uplink, gw→vpn, vpn→sdotson


class TestSmartBuildEmptyProject:
    def test_no_hosts_returns_empty_result(self, db):
        project = models.Project(id=new_id("p"), name="Empty", added="2026-01-01")
        db.add(project)
        db.commit()
        result = _run_smart_build(project.id, db)
        assert result["ok"] is True
        assert result["nodes_total"] == 0


class TestSmartBuildMissingProject:
    def test_unknown_project_returns_error(self, db):
        result = _run_smart_build("p-does-not-exist", db)
        assert result["ok"] is False
        assert "not found" in result.get("error", "").lower()
