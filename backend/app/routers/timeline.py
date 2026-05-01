from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models, schemas
from ..core.deps import get_current_user
from ..core.access import check_pid_access

router = APIRouter(prefix="/api/timeline", tags=["timeline"])


@router.get("", response_model=list[schemas.TimelineEvent])
def get_timeline(pid: str, entity: str | None = None, limit: int = 200, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    check_pid_access(db, pid, user, "timeline.read")
    q = db.query(models.TimelineEvent).filter(models.TimelineEvent.pid == pid)
    if entity:
        q = q.filter(models.TimelineEvent.entity == entity)
    return q.order_by(models.TimelineEvent.ts.desc()).limit(limit).all()
