"""
Attack graph endpoint.

GET /api/projects/{pid}/attack-graph
Returns nodes and edges for visualization.
"""
import logging
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models
from ..core.deps import get_current_user
from ..core.access import check_pid_access

logger = logging.getLogger(__name__)

router = APIRouter(tags=["attack_graph"])


@router.get("/api/projects/{pid}/attack-graph")
def get_attack_graph(
    pid: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    check_pid_access(db, pid, user, "findings.read")

    hosts = db.query(models.Host).filter(models.Host.pid == pid).all()
    creds = db.query(models.Cred).filter(models.Cred.pid == pid).all()
    attack_paths = db.query(models.AttackPath).filter(models.AttackPath.pid == pid).all()

    # Build nodes
    nodes = []
    attacker_host_ids = set()
    host_by_id = {}

    for h in hosts:
        host_by_id[h.id] = h
        node_type = "attacker" if h.is_attacker else "host"
        if h.is_attacker:
            attacker_host_ids.add(h.id)
        nodes.append({
            "id": h.id,
            "type": node_type,
            "label": h.hostname or h.ip,
            "ip": h.ip,
            "status": h.status,
            "is_attacker": h.is_attacker,
            "tags": h.tags or [],
            "os": h.os,
        })

    # Virtual attacker node if no attacker host exists
    virtual_attacker_id = "attacker_virtual"
    has_attacker_node = bool(attacker_host_ids)
    if not has_attacker_node:
        nodes.append({
            "id": virtual_attacker_id,
            "type": "attacker",
            "label": "Attacker",
            "ip": "",
            "status": "attacker",
            "is_attacker": True,
            "tags": [],
            "os": "",
        })

    # Determine source node for edges without explicit source
    default_source = next(iter(attacker_host_ids)) if attacker_host_ids else virtual_attacker_id

    # Build edges from credentials
    edges = []
    edge_id_counter = 0

    for cred in creds:
        target_host_ids = cred.host_ids or []
        if not target_host_ids:
            continue

        label = cred.username
        if cred.domain:
            label = f"{cred.domain}\\{cred.username}"

        for target_hid in target_host_ids:
            if target_hid not in host_by_id:
                continue
            edge_id_counter += 1
            edges.append({
                "id": f"cred_edge_{edge_id_counter}",
                "from": default_source,
                "to": target_hid,
                "label": label,
                "cred_id": cred.id,
                "cred_type": cred.type,
            })

    # Build edges from attack paths (steps linked by order)
    for path in attack_paths:
        steps = db.query(models.AttackStep).filter(
            models.AttackStep.path_id == path.id
        ).order_by(models.AttackStep.step_order).all()

        for i in range(len(steps) - 1):
            src_step = steps[i]
            dst_step = steps[i + 1]
            edge_id_counter += 1
            edges.append({
                "id": f"path_edge_{edge_id_counter}",
                "from": src_step.id,
                "to": dst_step.id,
                "label": dst_step.technique or dst_step.label or "",
                "cred_id": None,
                "cred_type": None,
            })
            # Also add step nodes if not already present
            _ensure_step_node(nodes, src_step)
            _ensure_step_node(nodes, dst_step)

    compromised_count = sum(1 for h in hosts if h.status == "compromised")

    return {
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "hosts": len(hosts),
            "edges": len(edges),
            "compromised": compromised_count,
        },
    }


def _ensure_step_node(nodes: list, step: models.AttackStep):
    """Add a step node if not already in the node list."""
    existing_ids = {n["id"] for n in nodes}
    if step.id not in existing_ids:
        nodes.append({
            "id": step.id,
            "type": "step",
            "label": step.label or step.technique or f"Step {step.step_order}",
            "ip": "",
            "status": "",
            "is_attacker": False,
            "tags": [],
            "os": "",
        })
