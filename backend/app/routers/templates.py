import io
import json

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from typing import Annotated
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.utils import (
    list_default_finding_templates,
    list_default_snippets,
    new_id,
    norm_text,
    ts_now,
)
from ..database import get_db

router = APIRouter(
    tags=["templates"],
    responses={
        404: {"description": "Not found"},
        409: {"description": "Conflict"},
    },
)


# ── Finding Templates ─────────────────────────────────────────────────


@router.get("/api/finding-templates", response_model=list[schemas.FindingTemplate])
def list_finding_templates(db: Annotated[Session, Depends(get_db)]):
    custom = [
        {**schemas.FindingTemplate.model_validate(item).model_dump(), "is_custom": True}
        for item in db.query(models.FindingTemplate)
        .order_by(models.FindingTemplate.created_at.desc())
        .all()
    ]
    return custom + list_default_finding_templates()


@router.get("/api/finding-templates/custom", response_model=list[schemas.FindingTemplate])
def list_custom_finding_templates(db: Annotated[Session, Depends(get_db)]):
    return [
        {**schemas.FindingTemplate.model_validate(item).model_dump(), "is_custom": True}
        for item in db.query(models.FindingTemplate)
        .order_by(models.FindingTemplate.created_at.desc())
        .all()
    ]


@router.post(
    "/api/finding-templates/custom", response_model=schemas.FindingTemplate, status_code=201,
    responses={409: {"description": "Conflict"}},
)
def create_custom_finding_template(
    body: schemas.FindingTemplateCreate,
    db: Annotated[Session, Depends(get_db)],
):
    incoming = body.model_dump()
    existing = db.query(models.FindingTemplate).all()
    for item in existing:
        if all(
            [
                norm_text(item.title) == norm_text(incoming["title"]),
                norm_text(item.severity) == norm_text(incoming["severity"]),
                norm_text(item.cvss) == norm_text(incoming["cvss"]),
                norm_text(item.cve) == norm_text(incoming["cve"]),
                norm_text(item.description) == norm_text(incoming["description"]),
                norm_text(item.proof) == norm_text(incoming["proof"]),
                norm_text(item.recommendation) == norm_text(incoming["recommendation"]),
            ]
        ):
            raise HTTPException(
                409, "A custom finding template with the same content already exists"
            )
    item = models.FindingTemplate(id=new_id("ft"), created_at=ts_now(), **body.model_dump())
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


@router.delete("/api/finding-templates/custom/{tid}", status_code=204, responses={404: {"description": "Not found"}})
def delete_custom_finding_template(tid: str, db: Annotated[Session, Depends(get_db)]):
    item = db.query(models.FindingTemplate).filter(models.FindingTemplate.id == tid).first()
    if not item:
        raise HTTPException(404, "Template not found")
    db.delete(item)
    db.commit()


@router.get("/api/finding-templates/export")
def export_finding_templates(db: Annotated[Session, Depends(get_db)]):
    data = list_finding_templates(db)
    payload = json.dumps(data, ensure_ascii=False, indent=2).encode()
    return StreamingResponse(
        io.BytesIO(payload),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="finding_templates.json"'},
    )


@router.post("/api/finding-templates/import", status_code=201)
async def import_finding_templates(db: Annotated[Session, Depends(get_db)], file: Annotated[UploadFile, File(...)]):
    items = json.loads((await file.read()).decode())
    imported = 0
    existing = db.query(models.FindingTemplate).all()
    for item in items:
        if not item.get("is_custom"):
            continue
        duplicate = next(
            (
                x
                for x in existing
                if norm_text(x.title) == norm_text(item.get("title", ""))
                and norm_text(x.severity) == norm_text(item.get("severity", ""))
                and norm_text(x.cvss) == norm_text(item.get("cvss", ""))
                and norm_text(x.cve) == norm_text(item.get("cve", ""))
                and norm_text(x.description) == norm_text(item.get("description", ""))
                and norm_text(x.proof) == norm_text(item.get("proof", ""))
                and norm_text(x.recommendation) == norm_text(item.get("recommendation", ""))
            ),
            None,
        )
        if duplicate:
            continue
        obj = models.FindingTemplate(
            id=new_id("ft"),
            title=item.get("title", ""),
            severity=item.get("severity", "medium"),
            cvss=item.get("cvss", ""),
            cve=item.get("cve", ""),
            description=item.get("description", ""),
            proof=item.get("proof", ""),
            recommendation=item.get("recommendation", ""),
            created_at=ts_now(),
        )
        db.add(obj)
        existing.append(obj)
        imported += 1
    db.commit()
    return {"imported": imported}


# ── Custom Snippets ───────────────────────────────────────────────────


@router.get("/api/snippets", response_model=list[schemas.CustomSnippet])
def list_snippets(db: Annotated[Session, Depends(get_db)]):
    custom = [
        {**schemas.CustomSnippet.model_validate(item).model_dump(), "is_custom": True}
        for item in db.query(models.CustomSnippet)
        .order_by(models.CustomSnippet.created_at.desc())
        .all()
    ]
    return custom + list_default_snippets()


@router.get("/api/snippets/custom", response_model=list[schemas.CustomSnippet])
def list_custom_snippets(db: Annotated[Session, Depends(get_db)]):
    return [
        {**schemas.CustomSnippet.model_validate(item).model_dump(), "is_custom": True}
        for item in db.query(models.CustomSnippet)
        .order_by(models.CustomSnippet.created_at.desc())
        .all()
    ]


@router.post("/api/snippets/custom", response_model=schemas.CustomSnippet, status_code=201, responses={409: {"description": "Conflict"}})
def create_custom_snippet(body: schemas.CustomSnippetCreate, db: Annotated[Session, Depends(get_db)]):
    incoming = body.model_dump()
    incoming_tags = sorted([norm_text(t) for t in incoming.get("tags", []) if norm_text(t)])
    existing = db.query(models.CustomSnippet).all()
    for item in existing:
        item_tags = sorted([norm_text(t) for t in (item.tags or []) if norm_text(t)])
        if all(
            [
                norm_text(item.title) == norm_text(incoming["title"]),
                norm_text(item.category) == norm_text(incoming["category"]),
                norm_text(item.command) == norm_text(incoming["command"]),
                norm_text(item.opsec) == norm_text(incoming["opsec"]),
                item_tags == incoming_tags,
            ]
        ):
            raise HTTPException(409, "A custom snippet with the same content already exists")
    item = models.CustomSnippet(id=new_id("snp"), created_at=ts_now(), **body.model_dump())
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


@router.patch("/api/snippets/custom/{sid}", response_model=schemas.CustomSnippet, responses={404: {"description": "Not found"}, 409: {"description": "Conflict"}})
def update_custom_snippet(
    sid: str,
    body: schemas.CustomSnippetUpdate,
    db: Annotated[Session, Depends(get_db)],
):
    item = db.query(models.CustomSnippet).filter(models.CustomSnippet.id == sid).first()
    if not item:
        raise HTTPException(404, "Snippet not found")
    incoming = {
        "title": item.title,
        "category": item.category,
        "command": item.command,
        "tags": item.tags or [],
        "opsec": item.opsec,
        **body.model_dump(exclude_none=True),
    }
    incoming_tags = sorted([norm_text(t) for t in incoming.get("tags", []) if norm_text(t)])
    for other in db.query(models.CustomSnippet).filter(models.CustomSnippet.id != sid).all():
        other_tags = sorted([norm_text(t) for t in (other.tags or []) if norm_text(t)])
        if all(
            [
                norm_text(other.title) == norm_text(incoming["title"]),
                norm_text(other.category) == norm_text(incoming["category"]),
                norm_text(other.command) == norm_text(incoming["command"]),
                norm_text(other.opsec) == norm_text(incoming["opsec"]),
                other_tags == incoming_tags,
            ]
        ):
            raise HTTPException(409, "A custom snippet with the same content already exists")
    for key, value in body.model_dump(exclude_none=True).items():
        setattr(item, key, value)
    db.commit()
    db.refresh(item)
    return item


@router.delete("/api/snippets/custom/{sid}", status_code=204, responses={404: {"description": "Not found"}})
def delete_custom_snippet(sid: str, db: Annotated[Session, Depends(get_db)]):
    item = db.query(models.CustomSnippet).filter(models.CustomSnippet.id == sid).first()
    if not item:
        raise HTTPException(404, "Snippet not found")
    db.delete(item)
    db.commit()


@router.get("/api/snippets/export")
def export_snippets(db: Annotated[Session, Depends(get_db)]):
    data = list_snippets(db)
    payload = json.dumps(data, ensure_ascii=False, indent=2).encode()
    return StreamingResponse(
        io.BytesIO(payload),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="snippets.json"'},
    )


@router.post("/api/snippets/import", status_code=201)
async def import_snippets(db: Annotated[Session, Depends(get_db)], file: Annotated[UploadFile, File(...)]):
    items = json.loads((await file.read()).decode())
    imported = 0
    existing = db.query(models.CustomSnippet).all()
    for item in items:
        if not item.get("is_custom"):
            continue
        incoming_tags = sorted([norm_text(t) for t in item.get("tags", []) if norm_text(t)])
        duplicate = next(
            (
                x
                for x in existing
                if norm_text(x.title) == norm_text(item.get("title", ""))
                and norm_text(x.category) == norm_text(item.get("category", ""))
                and norm_text(x.command) == norm_text(item.get("command", ""))
                and norm_text(x.opsec) == norm_text(item.get("opsec", ""))
                and sorted([norm_text(t) for t in (x.tags or []) if norm_text(t)]) == incoming_tags
            ),
            None,
        )
        if duplicate:
            continue
        obj = models.CustomSnippet(
            id=new_id("snp"),
            title=item.get("title", ""),
            category=item.get("category", "Misc"),
            command=item.get("command", ""),
            tags=item.get("tags", []),
            opsec=item.get("opsec", ""),
            created_at=ts_now(),
        )
        db.add(obj)
        existing.append(obj)
        imported += 1
    db.commit()
    return {"imported": imported}
