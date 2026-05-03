"""Host business logic extracted from the hosts router."""
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.events import bcast, log_event
from ..core.utils import new_id


class HostService:
    def __init__(self, db: Session):
        self.db = db

    def get(self, host_id: str, pid: Optional[str] = None) -> Optional[models.Host]:
        q = self.db.query(models.Host).filter(models.Host.id == host_id)
        if pid:
            q = q.filter(models.Host.pid == pid)
        return q.first()

    def list_for_project(self, pid: str) -> list[models.Host]:
        return self.db.query(models.Host).filter(models.Host.pid == pid).all()

    def create(self, data: schemas.HostCreate, username: Optional[str] = None) -> models.Host:
        host = models.Host(**data.model_dump(), id=new_id("h"))
        self.db.add(host)
        log_event(
            self.db, host.pid, username, "host", "create",
            f"Host added: {host.ip or host.hostname}",
            {"ip": host.ip, "os": host.os},
        )
        self.db.commit()
        self.db.refresh(host)
        bcast(host.pid, "host", "create", schemas.Host.model_validate(host).model_dump())
        return host

    def update(self, host: models.Host, data: schemas.HostUpdate, username: Optional[str] = None) -> models.Host:
        for field, value in data.model_dump(exclude_none=True).items():
            setattr(host, field, value)
        log_event(
            self.db, host.pid, username, "host", "update",
            f"Host updated: {host.ip or host.hostname}",
            {"ip": host.ip},
        )
        self.db.commit()
        self.db.refresh(host)
        bcast(host.pid, "host", "update", schemas.Host.model_validate(host).model_dump())
        return host

    def delete(self, host: models.Host, username: Optional[str] = None) -> None:
        pid = host.pid
        label = host.ip or host.hostname or host.id
        self.db.delete(host)
        log_event(self.db, pid, username, "host", "delete", f"Host deleted: {label}", {"id": host.id})
        self.db.commit()
        bcast(pid, "host", "delete", {"id": host.id})
