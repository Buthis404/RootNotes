"""Attack graph API tests for access-edge semantics."""
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app import models
from app.core.utils import new_id


def _setup_and_login(client: TestClient) -> dict:
    client.post("/api/auth/setup", json={"username": "admin", "password": "testpass"})
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "testpass"})
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _create_project(client: TestClient, headers: dict) -> str:
    resp = client.post("/api/projects", json={"name": "Graph Project", "ip": "", "added": "2024-01-01"}, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def test_attack_graph_includes_verified_access_edges(client: TestClient, db: Session):
    headers = _setup_and_login(client)
    pid = _create_project(client, headers)

    attacker = models.Host(
        id=new_id("hst"), pid=pid, ip="10.0.0.10", hostname="attacker", os="Linux",
        status="alive", ports=[], services=[], tags=["attacker"], notes="", domain="",
        role="attacker", is_attacker=True,
    )
    target = models.Host(
        id=new_id("hst"), pid=pid, ip="10.0.0.20", hostname="dc01", os="Windows Server",
        status="access", ports=["445/tcp", "5985/tcp"], services=[], tags=["dc"], notes="", domain="corp.local",
        role="dc", is_attacker=False,
    )
    cred = models.Cred(
        id=new_id("crd"), pid=pid, username="administrator", secret="x", type="ntlm",
        service="smb", host="", domain="corp.local", cracked=False, notes="", tags=[],
        host_ids=[target.id], is_domain=True,
    )
    network = models.Network(
        id=new_id("net"), pid=pid, name="Default Network", background="#07080b",
        nodes_json=[
            {"id": "n_att", "host_id": attacker.id, "label": "attacker", "ip": attacker.ip, "zone_type": "external"},
            {"id": "n_tgt", "host_id": target.id, "label": "dc01", "ip": target.ip, "zone_type": "internal"},
        ],
        edges_json=[
            {
                "id": "edg1",
                "from": "n_att",
                "to": "n_tgt",
                "type": "local_admin",
                "label": "local admin",
                "confidence": 1.0,
                "source": "cred_validation",
                "reason": "Credential validated via SMB",
                "state": "observed",
                "verified": True,
            }
        ],
        meta_json={},
    )
    db.add_all([attacker, target, cred, network])
    db.commit()

    resp = client.get(f"/api/projects/{pid}/attack-graph", headers=headers)
    assert resp.status_code == 200, resp.text
    data = resp.json()

    access_edges = [edge for edge in data["edges"] if edge.get("kind") == "access"]
    credential_edges = [edge for edge in data["edges"] if edge.get("kind") == "credential"]
    assert len(access_edges) == 1
    assert len(credential_edges) == 1

    edge = access_edges[0]
    assert edge["from"] == attacker.id
    assert edge["to"] == target.id
    assert edge["verified"] is True
    assert edge["source"] == "cred_validation"
    assert edge["access_type"] == "local_admin"

    target_node = next(node for node in data["nodes"] if node["id"] == target.id)
    assert target_node["zone_type"] == "internal"
    assert target_node["role"] == "dc"
    assert target_node["reachability"]["reachable"] is True
    assert target_node["reachability"]["reachable_via_verified_path"] is True
    assert target_node["reachability"]["distance"] == 1
    assert target_node["reachability"]["verified_distance"] == 1
    assert data["stats"]["access_edges"] == 1
    assert data["stats"]["verified_access_edges"] == 1
    assert data["stats"]["reachable_hosts"] == 1
    assert data["stats"]["verified_reachable_hosts"] == 1
