"""
Project members management API.
"""
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models
from ..core.deps import get_current_user
from ..core.permissions import (
    get_membership, get_permissions_for_role, add_project_owner,
    PROJECT_ROLES, user_has_permission,
)
from ..core.utils import new_id, ts_now

router = APIRouter(prefix="/api/projects", tags=["members"])


class MemberOut(BaseModel):
    user_id: str
    username: str
    role: str
    created_at: str
    created_by: Optional[str] = None
    is_active: bool


class AddMemberBody(BaseModel):
    user_id: str
    role: str = "viewer"


class BulkAddMembersBody(BaseModel):
    user_ids: list[str]
    role: str = "viewer"


class UpdateRoleBody(BaseModel):
    role: str


class TransferOwnershipBody(BaseModel):
    user_id: str


class AvailableUserOut(BaseModel):
    id: str
    username: str
    role: str
    active: bool


def _get_project_or_404(pid: str, db: Session) -> models.Project:
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        raise HTTPException(404, "Project not found")
    return project


def _require_manage_members(pid: str, user: models.User, db: Session):
    if user.role == "admin":
        return
    if not user_has_permission(db, pid, user, "project.manage_members"):
        raise HTTPException(403, "Insufficient permissions to manage members")


def _upsert_member(pid: str, user_id: str, role: str, actor_id: str, db: Session) -> models.ProjectMember:
    existing = db.query(models.ProjectMember).filter(
        models.ProjectMember.project_id == pid,
        models.ProjectMember.user_id == user_id,
    ).first()
    if existing:
        existing.role = role
        existing.is_active = True
        existing.created_by = actor_id
        return existing

    member = models.ProjectMember(
        id=new_id("pm"),
        project_id=pid,
        user_id=user_id,
        role=role,
        created_at=ts_now(),
        created_by=actor_id,
        is_active=True,
    )
    db.add(member)
    return member


@router.get("/{pid}/members", response_model=list[MemberOut])
def list_members(
    pid: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    _get_project_or_404(pid, db)
    if user.role != "admin":
        membership = get_membership(db, pid, user.id)
        if not membership:
            raise HTTPException(404, "Project not found")

    members = (
        db.query(models.ProjectMember, models.User)
        .join(models.User, models.ProjectMember.user_id == models.User.id)
        .filter(models.ProjectMember.project_id == pid, models.ProjectMember.is_active == True)
        .all()
    )
    return [
        MemberOut(
            user_id=m.user_id,
            username=u.username,
            role=m.role,
            created_at=m.created_at,
            created_by=m.created_by,
            is_active=m.is_active,
        )
        for m, u in members
    ]


@router.post("/{pid}/members", status_code=201, response_model=MemberOut)
def add_member(
    pid: str,
    body: AddMemberBody,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    _get_project_or_404(pid, db)
    _require_manage_members(pid, user, db)

    if body.role not in PROJECT_ROLES:
        raise HTTPException(400, f"Invalid role. Valid roles: {PROJECT_ROLES}")

    if body.role == "owner" and user.role != "admin":
        caller_membership = get_membership(db, pid, user.id)
        if not caller_membership or caller_membership.role != "owner":
            raise HTTPException(403, "Only owners can assign the owner role")

    target_user = db.query(models.User).filter(models.User.id == body.user_id, models.User.active == True).first()
    if not target_user:
        raise HTTPException(404, "User not found")

    member = _upsert_member(pid, body.user_id, body.role, user.id, db)
    db.commit()
    db.refresh(member)
    return MemberOut(user_id=member.user_id, username=target_user.username, role=member.role,
                     created_at=member.created_at, created_by=member.created_by, is_active=member.is_active)


@router.post("/{pid}/members/bulk", status_code=201, response_model=list[MemberOut])
def bulk_add_members(
    pid: str,
    body: BulkAddMembersBody,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    _get_project_or_404(pid, db)
    _require_manage_members(pid, user, db)

    if body.role not in PROJECT_ROLES:
        raise HTTPException(400, f"Invalid role. Valid roles: {PROJECT_ROLES}")
    if not body.user_ids:
        raise HTTPException(400, "No users provided")
    if body.role == "owner" and user.role != "admin":
        caller_membership = get_membership(db, pid, user.id)
        if not caller_membership or caller_membership.role != "owner":
            raise HTTPException(403, "Only owners can assign the owner role")

    user_ids = list(dict.fromkeys(uid for uid in body.user_ids if uid))
    target_users = db.query(models.User).filter(models.User.id.in_(user_ids), models.User.active == True).all()
    target_map = {u.id: u for u in target_users}
    missing_ids = [uid for uid in user_ids if uid not in target_map]
    if missing_ids:
        raise HTTPException(404, f"Users not found: {', '.join(missing_ids[:5])}")

    members = []
    for uid in user_ids:
        member = _upsert_member(pid, uid, body.role, user.id, db)
        members.append(member)

    db.commit()
    for member in members:
        db.refresh(member)

    return [
        MemberOut(
            user_id=member.user_id,
            username=target_map[member.user_id].username,
            role=member.role,
            created_at=member.created_at,
            created_by=member.created_by,
            is_active=member.is_active,
        )
        for member in members
    ]


@router.get("/{pid}/available-users", response_model=list[AvailableUserOut])
def list_available_users(
    pid: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    _get_project_or_404(pid, db)
    _require_manage_members(pid, user, db)

    active_member_ids = db.query(models.ProjectMember.user_id).filter(
        models.ProjectMember.project_id == pid,
        models.ProjectMember.is_active == True,
    ).all()
    member_ids = [uid for (uid,) in active_member_ids]

    query = db.query(models.User).filter(models.User.active == True)
    if member_ids:
        query = query.filter(~models.User.id.in_(member_ids))

    users = query.order_by(models.User.username).all()
    return [AvailableUserOut(id=u.id, username=u.username, role=u.role, active=u.active) for u in users]


@router.patch("/{pid}/members/{target_uid}", response_model=MemberOut)
def update_member_role(
    pid: str,
    target_uid: str,
    body: UpdateRoleBody,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    _get_project_or_404(pid, db)
    _require_manage_members(pid, user, db)

    if body.role not in PROJECT_ROLES:
        raise HTTPException(400, f"Invalid role. Valid roles: {PROJECT_ROLES}")

    target_membership = db.query(models.ProjectMember).filter(
        models.ProjectMember.project_id == pid,
        models.ProjectMember.user_id == target_uid,
        models.ProjectMember.is_active == True,
    ).first()
    if not target_membership:
        raise HTTPException(404, "Member not found")

    target_user = db.query(models.User).filter(models.User.id == target_uid).first()

    if target_membership.role == "owner" and user.role != "admin":
        caller_membership = get_membership(db, pid, user.id)
        if not caller_membership or caller_membership.role != "owner":
            raise HTTPException(403, "Cannot change role of project owner")

    if body.role == "owner" and user.role != "admin":
        caller_membership = get_membership(db, pid, user.id)
        if not caller_membership or caller_membership.role != "owner":
            raise HTTPException(403, "Only owners can assign the owner role")

    target_membership.role = body.role
    db.commit()
    db.refresh(target_membership)
    return MemberOut(user_id=target_membership.user_id, username=target_user.username if target_user else target_uid,
                     role=target_membership.role, created_at=target_membership.created_at,
                     created_by=target_membership.created_by, is_active=target_membership.is_active)


@router.delete("/{pid}/members/{target_uid}", status_code=204)
def remove_member(
    pid: str,
    target_uid: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    _get_project_or_404(pid, db)
    _require_manage_members(pid, user, db)

    target_membership = db.query(models.ProjectMember).filter(
        models.ProjectMember.project_id == pid,
        models.ProjectMember.user_id == target_uid,
        models.ProjectMember.is_active == True,
    ).first()
    if not target_membership:
        raise HTTPException(404, "Member not found")

    if target_membership.role == "owner" and user.role != "admin":
        caller_membership = get_membership(db, pid, user.id)
        if not caller_membership or caller_membership.role != "owner":
            raise HTTPException(403, "Cannot remove project owner")

    if target_membership.role == "owner":
        owner_count = db.query(models.ProjectMember).filter(
            models.ProjectMember.project_id == pid,
            models.ProjectMember.role == "owner",
            models.ProjectMember.is_active == True,
        ).count()
        if owner_count <= 1:
            raise HTTPException(400, "Cannot remove the last owner of a project")

    target_membership.is_active = False
    db.commit()


@router.post("/{pid}/transfer-ownership", status_code=200)
def transfer_ownership(
    pid: str,
    body: TransferOwnershipBody,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    _get_project_or_404(pid, db)

    if user.role != "admin":
        caller_membership = get_membership(db, pid, user.id)
        if not caller_membership or caller_membership.role != "owner":
            raise HTTPException(403, "Only project owner can transfer ownership")

    target_user = db.query(models.User).filter(models.User.id == body.user_id, models.User.active == True).first()
    if not target_user:
        raise HTTPException(404, "Target user not found")

    add_project_owner(db, pid, body.user_id, created_by=user.id)

    if user.role != "admin":
        caller_membership = get_membership(db, pid, user.id)
        if caller_membership and caller_membership.user_id != body.user_id:
            caller_membership.role = "admin"

    db.commit()
    return {"message": "Ownership transferred successfully"}


@router.get("/{pid}/permissions/me")
def get_my_permissions(
    pid: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    _get_project_or_404(pid, db)

    if user.role == "admin":
        from ..core.permissions import ROLE_PERMISSIONS
        all_perms = set()
        for perms in ROLE_PERMISSIONS.values():
            all_perms |= perms
        return {
            "project_id": pid,
            "role": "super_admin",
            "permissions": sorted(all_perms),
            "is_super_admin": True,
        }

    membership = get_membership(db, pid, user.id)
    if not membership:
        raise HTTPException(404, "Project not found")

    return {
        "project_id": pid,
        "role": membership.role,
        "permissions": sorted(get_permissions_for_role(membership.role)),
        "is_super_admin": False,
    }
