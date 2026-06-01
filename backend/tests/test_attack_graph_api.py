"""
Tests for attack graph endpoint.
"""

import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app import models
from app.core.utils import new_id

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
TS = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient, module_db: Session):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    r = module_client.post("/api/projects", json={"name": "AttackGraphTest", "added": TS, "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]

    attacker = models.Host(
        id=new_id("hst"), pid=_state["pid"], ip="10.200.0.10", hostname="atk01",
        os="Kali", status="attacker", ports=[], services=[], tags=["attacker"],
        notes="", domain="", role="attacker", is_attacker=True,
    )
    target = models.Host(
        id=new_id("hst"), pid=_state["pid"], ip="10.200.0.20", hostname="dc01",
        os="Windows Server 2022", status="access", ports=["88/tcp", "389/tcp", "445/tcp"],
        services=[], tags=["dc"], notes="", domain="test.local",
        role="domain_controller", is_attacker=False,
    )
    ws = models.Host(
        id=new_id("hst"), pid=_state["pid"], ip="10.200.0.30", hostname="ws01",
        os="Windows 10", status="alive", ports=["445/tcp"],
        services=[], tags=[], notes="", domain="test.local",
        role="workstation", is_attacker=False,
    )
    cred = models.Cred(
        id=new_id("crd"), pid=_state["pid"], username="admin", secret="P@ss",
        type="plain", service="smb", host="", domain="test.local", cracked=False,
        notes="", tags=[], host_ids=[target.id, ws.id], is_domain=True,
    )
    module_db.add_all([attacker, target, ws, cred])
    module_db.commit()
    _state["attacker_id"] = attacker.id
    _state["target_id"] = target.id
    _state["ws_id"] = ws.id
    _state["cred_id"] = cred.id
    yield
    module_client.post("/api/auth/logout")


class TestAttackGraph:
    def test_get_attack_graph(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/attack-graph")
        assert r.status_code == 200, r.text
        data = r.json()
        assert "nodes" in data
        assert "edges" in data
        assert "stats" in data

    def test_attack_graph_has_hosts(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/attack-graph")
        data = r.json()
        node_ids = {n["id"] for n in data["nodes"]}
        assert _state["attacker_id"] in node_ids
        assert _state["target_id"] in node_ids

    def test_attack_graph_credential_edges(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/attack-graph")
        data = r.json()
        cred_edges = [e for e in data["edges"] if e.get("kind") == "credential"]
        assert len(cred_edges) >= 1

    def test_attack_graph_reachability(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/attack-graph")
        data = r.json()
        for node in data["nodes"]:
            assert "reachability" in node
            assert "privilege_info" in node

    def test_attack_graph_stats(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/attack-graph")
        data = r.json()
        stats = data["stats"]
        assert stats["hosts"] >= 3
        assert stats["edges"] >= 1


class TestAttackGraphHelpers:
    def test_is_access_edge(self):
        from app.routers.attack_graph import _is_access_edge
        assert _is_access_edge({"type": "ssh"}) is True
        assert _is_access_edge({"source": "cred_validation"}) is True
        assert _is_access_edge({"type": "same_subnet"}) is False
        assert _is_access_edge({"style": "exploit"}) is True

    def test_is_dc(self):
        from app.routers.attack_graph import _is_dc

        class H:
            role = "domain_controller"
            tags = []
            ports = []

        assert _is_dc(H()) is True

        class H2:
            role = "server"
            tags = ["dc"]
            ports = []

        assert _is_dc(H2()) is True

    def test_bfs_dist(self):
        from app.routers.attack_graph import _bfs_dist
        adj = {"a": ["b"], "b": ["c"]}
        dist = _bfs_dist(adj, ["a"])
        assert dist["a"] == 0
        assert dist["b"] == 1
        assert dist["c"] == 2
        assert "d" not in dist
