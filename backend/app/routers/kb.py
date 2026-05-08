"""
Knowledge Base router.

GET    /api/kb?pid=&category=&q=   list articles
POST   /api/kb                     create article
GET    /api/kb/{aid}               get single article
PATCH  /api/kb/{aid}               update article
DELETE /api/kb/{aid}               delete article (204)
"""
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models, schemas
from ..core.deps import get_current_user
from ..core.utils import new_id

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/kb", tags=["kb"])


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


@router.get("", response_model=list[schemas.KBArticle])
def list_kb_articles(
    pid: Optional[str] = None,
    category: Optional[str] = None,
    q: Optional[str] = None,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    if pid:
        # Return global (pid IS NULL) + project articles
        query = db.query(models.KBArticle).filter(
            (models.KBArticle.pid == None) | (models.KBArticle.pid == pid)
        )
    else:
        # Return only global articles
        query = db.query(models.KBArticle).filter(models.KBArticle.pid == None)

    if category:
        query = query.filter(models.KBArticle.category == category)

    articles = query.all()

    if q:
        q_lower = q.lower()
        articles = [
            a for a in articles
            if q_lower in a.title.lower() or q_lower in (a.content or "").lower()
        ]

    return articles


@router.post("", response_model=schemas.KBArticle, status_code=201)
def create_kb_article(
    body: schemas.KBArticleCreate,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    # If project-scoped, validate access
    if body.pid:
        from ..core.access import check_pid_access
        check_pid_access(db, body.pid, user)

    now = _now()
    article = models.KBArticle(
        id=new_id("kb"),
        pid=body.pid,
        title=body.title,
        content=body.content,
        category=body.category,
        tags=body.tags or [],
        created_by=user.username,
        created_at=now,
        updated_at=now,
    )
    db.add(article)
    db.commit()
    db.refresh(article)
    return article


@router.get("/{aid}", response_model=schemas.KBArticle)
def get_kb_article(
    aid: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    article = db.query(models.KBArticle).filter(models.KBArticle.id == aid).first()
    if not article:
        raise HTTPException(404, "Article not found")
    return article


@router.patch("/{aid}", response_model=schemas.KBArticle)
def update_kb_article(
    aid: str,
    body: schemas.KBArticleUpdate,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    article = db.query(models.KBArticle).filter(models.KBArticle.id == aid).first()
    if not article:
        raise HTTPException(404, "Article not found")

    for k, v in body.model_dump(exclude_none=True).items():
        setattr(article, k, v)
    article.updated_at = _now()

    db.commit()
    db.refresh(article)
    return article


@router.delete("/{aid}", status_code=204)
def delete_kb_article(
    aid: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    article = db.query(models.KBArticle).filter(models.KBArticle.id == aid).first()
    if not article:
        raise HTTPException(404, "Article not found")
    db.delete(article)
    db.commit()
