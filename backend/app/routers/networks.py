from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models, schemas
from ..core.events import bcast
from ..core.utils import new_id
from ..core.deps import get_current_user
from ..core.access import check_pid_access, check_object_access, get_user_member_pids
from ..core.network_data import (
    get_nodes, get_edges, get_regions,
    replace_nodes, replace_edges, replace_regions,
)

router = APIRouter(prefix="/api/networks", tags=["networks"])


def _net_out(net: models.Network, db: Session) -> schemas.Network:
    """Build Network schema reading nodes/edges/regions from dedicated tables."""
    obj = schemas.Network.from_orm_obj(net)
    obj.nodes = get_nodes(net.id, db)
    obj.edges = get_edges(net.id, db)
    obj.regions = get_regions(net.id, db)
    return obj


@router.get("", response_model=list[schemas.Network])
def list_networks(pid: str | None = None, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    if pid:
        check_pid_access(db, pid, user, "network.read")
        nets = db.query(models.Network).filter(models.Network.pid == pid).all()
    elif user.role == "admin":
        nets = db.query(models.Network).all()
    else:
        member_pids = get_user_member_pids(db, user)
        nets = db.query(models.Network).filter(models.Network.pid.in_(member_pids)).all()
    return [_net_out(n, db) for n in nets]


@router.post("", response_model=schemas.Network, status_code=201)
def create_network(body: schemas.NetworkCreate, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    check_pid_access(db, body.pid, user, "network.update")
    net = models.Network(
        id=new_id("net"), pid=body.pid, name=body.name,
        background=body.background, meta_json={},
    )
    db.add(net)
    db.commit()
    db.refresh(net)
    result = _net_out(net, db)
    bcast(body.pid, "network", "create", result.model_dump())
    return result


@router.patch("/{nid}", response_model=schemas.Network)
def update_network(nid: str, body: schemas.NetworkUpdate, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    net = db.query(models.Network).filter(models.Network.id == nid).first()
    if not net:
        raise HTTPException(404, "Network not found")
    check_object_access(db, net.pid, user, "network.update")
    if body.name is not None:
        net.name = body.name
    if body.background is not None:
        net.background = body.background
    if body.meta is not None:
        net.meta_json = body.meta
    if body.regions is not None:
        replace_regions(net.id, net.pid, body.regions, db)
    if body.nodes is not None:
        replace_nodes(net.id, net.pid, body.nodes, db)
    if body.edges is not None:
        replace_edges(net.id, net.pid, body.edges, db)
    db.commit()
    db.refresh(net)
    result = _net_out(net, db)
    bcast(net.pid, "network", "update", result.model_dump())
    return result


@router.delete("/{nid}", status_code=204)
def delete_network(nid: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    net = db.query(models.Network).filter(models.Network.id == nid).first()
    if not net:
        raise HTTPException(404, "Network not found")
    check_object_access(db, net.pid, user, "network.update")
    pid = net.pid
    db.delete(net)  # CASCADE deletes network_nodes/edges/regions
    db.commit()
    bcast(pid, "network", "delete", {"id": nid})
