"""Project business logic extracted from the projects router."""
from typing import Optional

from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.deps import is_admin
from ..core.permissions import add_project_owner
from ..core.utils import new_id


class ProjectService:
    def __init__(self, db: Session):
        self.db = db

    def get(self, project_id: str) -> Optional[models.Project]:
        return self.db.query(models.Project).filter(models.Project.id == project_id).first()

    def list_for_user(self, user: models.User) -> list[models.Project]:
        if is_admin(user):
            return self.db.query(models.Project).all()
        member_pids = [
            m.project_id
            for m in self.db.query(models.ProjectMember).filter(
                models.ProjectMember.user_id == user.id,
                models.ProjectMember.is_active == True,
            ).all()
        ]
        return self.db.query(models.Project).filter(models.Project.id.in_(member_pids)).all()

    def create(self, data: schemas.ProjectCreate, owner_user_id: str) -> models.Project:
        project = models.Project(**data.model_dump(), id=new_id("p"))
        self.db.add(project)
        self.db.flush()
        add_project_owner(self.db, project.id, owner_user_id, created_by=owner_user_id)
        self.db.commit()
        self.db.refresh(project)
        return project

    def update(self, project: models.Project, data: schemas.ProjectUpdate) -> models.Project:
        for field, value in data.model_dump(exclude_none=True).items():
            setattr(project, field, value)
        self.db.commit()
        self.db.refresh(project)
        return project

    def delete(self, project: models.Project) -> None:
        self.db.delete(project)
        self.db.commit()
