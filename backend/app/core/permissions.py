"""
Project-level RBAC — role→permission data layer.

Global roles (User.role):
  admin  — super_admin: sees all projects, bypasses project checks
  user   — normal user: sees only member projects
  viewer — legacy read-only: same scope as user but blocked from writes
           at middleware level

Project roles: owner > admin > editor > operator > viewer > auditor

Runtime enforcement (check_pid_access / user_has_permission) lives in
`access.py` — this module is pure data + membership lookup + the
add_project_owner mutation helper.
"""

from sqlalchemy.orm import Session

from .. import models
from .enums import MemberRole
from .utils import new_id, ts_now

# ── Permission constants ──────────────────────────────────────────────
PERM_PROJECT_READ = "project.read"
PERM_PROJECT_UPDATE = "project.update"
PERM_PROJECT_DELETE = "project.delete"
PERM_PROJECT_MANAGE_MEMBERS = "project.manage_members"
PERM_PROJECT_EXPORT = "project.export"
PERM_PROJECT_IMPORT = "project.import"
PERM_PROJECT_TRANSFER_OWNERSHIP = "project.transfer_ownership"

PERM_HOSTS_READ = "hosts.read"
PERM_HOSTS_CREATE = "hosts.create"
PERM_HOSTS_UPDATE = "hosts.update"
PERM_HOSTS_DELETE = "hosts.delete"

PERM_CREDENTIALS_READ = "credentials.read"
PERM_CREDENTIALS_READ_SECRET = "credentials.read_secret"
PERM_CREDENTIALS_CREATE = "credentials.create"
PERM_CREDENTIALS_UPDATE = "credentials.update"
PERM_CREDENTIALS_DELETE = "credentials.delete"

PERM_FINDINGS_READ = "findings.read"
PERM_FINDINGS_CREATE = "findings.create"
PERM_FINDINGS_UPDATE = "findings.update"
PERM_FINDINGS_DELETE = "findings.delete"

PERM_NOTES_READ = "notes.read"
PERM_NOTES_CREATE = "notes.create"
PERM_NOTES_UPDATE = "notes.update"
PERM_NOTES_DELETE = "notes.delete"

PERM_LOOT_READ = "loot.read"
PERM_LOOT_CREATE = "loot.create"
PERM_LOOT_UPDATE = "loot.update"
PERM_LOOT_DELETE = "loot.delete"

PERM_NETWORK_READ = "network.read"
PERM_NETWORK_UPDATE = "network.update"
PERM_NETWORK_MANAGE_NODES = "network.manage_nodes"
PERM_NETWORK_MANAGE_LINKS = "network.manage_links"

PERM_TOPOLOGY_READ = "topology.read"
PERM_TOPOLOGY_GENERATE_COMMANDS = "topology.generate_commands"
PERM_TOPOLOGY_PREVIEW = "topology.preview"
PERM_TOPOLOGY_APPLY = "topology.apply"

PERM_REPORTS_READ = "reports.read"
PERM_REPORTS_GENERATE = "reports.generate"
PERM_REPORTS_UPDATE_TEMPLATES = "reports.update_templates"
PERM_REPORTS_EXPORT = "reports.export"

PERM_TIMELINE_READ = "timeline.read"
PERM_TIMELINE_CREATE = "timeline.create"

PERM_SCOPES_READ = "scopes.read"
PERM_SCOPES_UPDATE = "scopes.update"

PERM_ATTACK_PATHS_READ = "attack_paths.read"
PERM_ATTACK_PATHS_UPDATE = "attack_paths.update"

PERM_COMMAND_OUTPUTS_READ = "command_outputs.read"
PERM_COMMAND_OUTPUTS_CREATE = "command_outputs.create"
PERM_COMMAND_OUTPUTS_UPDATE = "command_outputs.update"
PERM_COMMAND_OUTPUTS_DELETE = "command_outputs.delete"

PERM_CHECKLIST_READ = "checklist.read"
PERM_CHECKLIST_UPDATE = "checklist.update"

PERM_OBJECTIVES_READ = "objectives.read"
PERM_OBJECTIVES_CREATE = "objectives.create"
PERM_OBJECTIVES_UPDATE = "objectives.update"
PERM_OBJECTIVES_DELETE = "objectives.delete"

PERM_SEARCH_READ = "search.read"

PERM_KB_READ = "kb.read"
PERM_KB_CREATE = "kb.create"
PERM_KB_UPDATE = "kb.update"
PERM_KB_DELETE = "kb.delete"
PERM_KB_EXPORT = "kb.export"

PERM_PLAYBOOKS_READ = "playbooks.read"
PERM_PLAYBOOKS_CREATE = "playbooks.create"
PERM_PLAYBOOKS_UPDATE = "playbooks.update"
PERM_PLAYBOOKS_DELETE = "playbooks.delete"

PERM_JOBS_READ = "jobs.read"
PERM_JOBS_CANCEL = "jobs.cancel"

PERM_PIVOTS_READ = "pivots.read"
PERM_PIVOTS_MANAGE = "pivots.manage"

PERM_WEBHOOKS_READ = "webhooks.read"
PERM_WEBHOOKS_MANAGE = "webhooks.manage"

PERM_SCANS_RUN = "scans.run"
PERM_SCANS_READ = "scans.read"

# ── Permission strings ────────────────────────────────────────────────
ROLE_PERMISSIONS: dict[str, set[str]] = {
    "owner": {
        PERM_PROJECT_READ,
        PERM_PROJECT_UPDATE,
        PERM_PROJECT_DELETE,
        PERM_PROJECT_MANAGE_MEMBERS,
        PERM_PROJECT_EXPORT,
        PERM_PROJECT_IMPORT,
        PERM_PROJECT_TRANSFER_OWNERSHIP,
        PERM_HOSTS_READ,
        PERM_HOSTS_CREATE,
        PERM_HOSTS_UPDATE,
        PERM_HOSTS_DELETE,
        PERM_CREDENTIALS_READ,
        PERM_CREDENTIALS_READ_SECRET,
        PERM_CREDENTIALS_CREATE,
        PERM_CREDENTIALS_UPDATE,
        PERM_CREDENTIALS_DELETE,
        PERM_FINDINGS_READ,
        PERM_FINDINGS_CREATE,
        PERM_FINDINGS_UPDATE,
        PERM_FINDINGS_DELETE,
        PERM_NOTES_READ,
        PERM_NOTES_CREATE,
        PERM_NOTES_UPDATE,
        PERM_NOTES_DELETE,
        PERM_LOOT_READ,
        PERM_LOOT_CREATE,
        PERM_LOOT_UPDATE,
        PERM_LOOT_DELETE,
        PERM_NETWORK_READ,
        PERM_NETWORK_UPDATE,
        PERM_NETWORK_MANAGE_NODES,
        PERM_NETWORK_MANAGE_LINKS,
        PERM_TOPOLOGY_READ,
        PERM_TOPOLOGY_GENERATE_COMMANDS,
        PERM_TOPOLOGY_PREVIEW,
        PERM_TOPOLOGY_APPLY,
        PERM_REPORTS_READ,
        PERM_REPORTS_GENERATE,
        PERM_REPORTS_UPDATE_TEMPLATES,
        PERM_REPORTS_EXPORT,
        PERM_TIMELINE_READ,
        PERM_TIMELINE_CREATE,
        PERM_SCOPES_READ,
        PERM_SCOPES_UPDATE,
        PERM_ATTACK_PATHS_READ,
        PERM_ATTACK_PATHS_UPDATE,
        PERM_COMMAND_OUTPUTS_READ,
        PERM_COMMAND_OUTPUTS_CREATE,
        PERM_COMMAND_OUTPUTS_UPDATE,
        PERM_COMMAND_OUTPUTS_DELETE,
        PERM_CHECKLIST_READ,
        PERM_CHECKLIST_UPDATE,
        PERM_OBJECTIVES_READ,
        PERM_OBJECTIVES_CREATE,
        PERM_OBJECTIVES_UPDATE,
        PERM_OBJECTIVES_DELETE,
        PERM_SEARCH_READ,
        PERM_KB_READ,
        PERM_KB_CREATE,
        PERM_KB_UPDATE,
        PERM_KB_DELETE,
        PERM_KB_EXPORT,
        PERM_PLAYBOOKS_READ,
        PERM_PLAYBOOKS_CREATE,
        PERM_PLAYBOOKS_UPDATE,
        PERM_PLAYBOOKS_DELETE,
        PERM_JOBS_READ,
        PERM_JOBS_CANCEL,
        PERM_PIVOTS_READ,
        PERM_PIVOTS_MANAGE,
        PERM_WEBHOOKS_READ,
        PERM_WEBHOOKS_MANAGE,
        PERM_SCANS_RUN,
        PERM_SCANS_READ,
    },
    "admin": {
        PERM_PROJECT_READ,
        PERM_PROJECT_UPDATE,
        PERM_PROJECT_MANAGE_MEMBERS,
        PERM_PROJECT_EXPORT,
        PERM_PROJECT_IMPORT,
        PERM_HOSTS_READ,
        PERM_HOSTS_CREATE,
        PERM_HOSTS_UPDATE,
        PERM_HOSTS_DELETE,
        PERM_CREDENTIALS_READ,
        PERM_CREDENTIALS_READ_SECRET,
        PERM_CREDENTIALS_CREATE,
        PERM_CREDENTIALS_UPDATE,
        PERM_CREDENTIALS_DELETE,
        PERM_FINDINGS_READ,
        PERM_FINDINGS_CREATE,
        PERM_FINDINGS_UPDATE,
        PERM_FINDINGS_DELETE,
        PERM_NOTES_READ,
        PERM_NOTES_CREATE,
        PERM_NOTES_UPDATE,
        PERM_NOTES_DELETE,
        PERM_LOOT_READ,
        PERM_LOOT_CREATE,
        PERM_LOOT_UPDATE,
        PERM_LOOT_DELETE,
        PERM_NETWORK_READ,
        PERM_NETWORK_UPDATE,
        PERM_NETWORK_MANAGE_NODES,
        PERM_NETWORK_MANAGE_LINKS,
        PERM_TOPOLOGY_READ,
        PERM_TOPOLOGY_GENERATE_COMMANDS,
        PERM_TOPOLOGY_PREVIEW,
        PERM_TOPOLOGY_APPLY,
        PERM_REPORTS_READ,
        PERM_REPORTS_GENERATE,
        PERM_REPORTS_UPDATE_TEMPLATES,
        PERM_REPORTS_EXPORT,
        PERM_TIMELINE_READ,
        PERM_TIMELINE_CREATE,
        PERM_SCOPES_READ,
        PERM_SCOPES_UPDATE,
        PERM_ATTACK_PATHS_READ,
        PERM_ATTACK_PATHS_UPDATE,
        PERM_COMMAND_OUTPUTS_READ,
        PERM_COMMAND_OUTPUTS_CREATE,
        PERM_COMMAND_OUTPUTS_UPDATE,
        PERM_COMMAND_OUTPUTS_DELETE,
        PERM_CHECKLIST_READ,
        PERM_CHECKLIST_UPDATE,
        PERM_OBJECTIVES_READ,
        PERM_OBJECTIVES_CREATE,
        PERM_OBJECTIVES_UPDATE,
        PERM_OBJECTIVES_DELETE,
        PERM_SEARCH_READ,
        PERM_KB_READ,
        PERM_KB_CREATE,
        PERM_KB_UPDATE,
        PERM_KB_DELETE,
        PERM_KB_EXPORT,
        PERM_PLAYBOOKS_READ,
        PERM_PLAYBOOKS_CREATE,
        PERM_PLAYBOOKS_UPDATE,
        PERM_PLAYBOOKS_DELETE,
        PERM_JOBS_READ,
        PERM_JOBS_CANCEL,
        PERM_PIVOTS_READ,
        PERM_PIVOTS_MANAGE,
        PERM_WEBHOOKS_READ,
        PERM_WEBHOOKS_MANAGE,
        PERM_SCANS_RUN,
        PERM_SCANS_READ,
    },
    "editor": {
        PERM_PROJECT_READ,
        PERM_PROJECT_EXPORT,
        PERM_HOSTS_READ,
        PERM_HOSTS_CREATE,
        PERM_HOSTS_UPDATE,
        PERM_HOSTS_DELETE,
        PERM_CREDENTIALS_READ,
        PERM_CREDENTIALS_READ_SECRET,
        PERM_CREDENTIALS_CREATE,
        PERM_CREDENTIALS_UPDATE,
        PERM_CREDENTIALS_DELETE,
        PERM_FINDINGS_READ,
        PERM_FINDINGS_CREATE,
        PERM_FINDINGS_UPDATE,
        PERM_FINDINGS_DELETE,
        PERM_NOTES_READ,
        PERM_NOTES_CREATE,
        PERM_NOTES_UPDATE,
        PERM_NOTES_DELETE,
        PERM_LOOT_READ,
        PERM_LOOT_CREATE,
        PERM_LOOT_UPDATE,
        PERM_LOOT_DELETE,
        PERM_NETWORK_READ,
        PERM_NETWORK_UPDATE,
        PERM_NETWORK_MANAGE_NODES,
        PERM_NETWORK_MANAGE_LINKS,
        PERM_TOPOLOGY_READ,
        PERM_TOPOLOGY_GENERATE_COMMANDS,
        PERM_TOPOLOGY_PREVIEW,
        PERM_TOPOLOGY_APPLY,
        PERM_REPORTS_READ,
        PERM_REPORTS_GENERATE,
        PERM_REPORTS_UPDATE_TEMPLATES,
        PERM_TIMELINE_READ,
        PERM_TIMELINE_CREATE,
        PERM_SCOPES_READ,
        PERM_SCOPES_UPDATE,
        PERM_ATTACK_PATHS_READ,
        PERM_ATTACK_PATHS_UPDATE,
        PERM_COMMAND_OUTPUTS_READ,
        PERM_COMMAND_OUTPUTS_CREATE,
        PERM_COMMAND_OUTPUTS_UPDATE,
        PERM_COMMAND_OUTPUTS_DELETE,
        PERM_CHECKLIST_READ,
        PERM_CHECKLIST_UPDATE,
        PERM_OBJECTIVES_READ,
        PERM_OBJECTIVES_CREATE,
        PERM_OBJECTIVES_UPDATE,
        PERM_OBJECTIVES_DELETE,
        PERM_SEARCH_READ,
        PERM_KB_READ,
        PERM_KB_CREATE,
        PERM_KB_UPDATE,
        PERM_KB_EXPORT,
        PERM_PLAYBOOKS_READ,
        PERM_PLAYBOOKS_CREATE,
        PERM_PLAYBOOKS_UPDATE,
        PERM_PLAYBOOKS_DELETE,
        PERM_JOBS_READ,
        PERM_JOBS_CANCEL,
        PERM_PIVOTS_READ,
        PERM_PIVOTS_MANAGE,
        PERM_WEBHOOKS_READ,
        PERM_SCANS_RUN,
        PERM_SCANS_READ,
    },
    "operator": {
        PERM_PROJECT_READ,
        PERM_HOSTS_READ,
        PERM_HOSTS_CREATE,
        PERM_HOSTS_UPDATE,
        PERM_CREDENTIALS_READ,
        PERM_CREDENTIALS_READ_SECRET,
        PERM_CREDENTIALS_CREATE,
        PERM_CREDENTIALS_UPDATE,
        PERM_FINDINGS_READ,
        PERM_FINDINGS_CREATE,
        PERM_FINDINGS_UPDATE,
        PERM_NOTES_READ,
        PERM_NOTES_CREATE,
        PERM_NOTES_UPDATE,
        PERM_LOOT_READ,
        PERM_LOOT_CREATE,
        PERM_LOOT_UPDATE,
        PERM_NETWORK_READ,
        PERM_TOPOLOGY_READ,
        PERM_TOPOLOGY_PREVIEW,
        PERM_REPORTS_READ,
        PERM_TIMELINE_READ,
        PERM_TIMELINE_CREATE,
        PERM_SCOPES_READ,
        PERM_ATTACK_PATHS_READ,
        PERM_COMMAND_OUTPUTS_READ,
        PERM_COMMAND_OUTPUTS_CREATE,
        PERM_COMMAND_OUTPUTS_UPDATE,
        PERM_CHECKLIST_READ,
        PERM_CHECKLIST_UPDATE,
        PERM_OBJECTIVES_READ,
        PERM_OBJECTIVES_UPDATE,
        PERM_SEARCH_READ,
        PERM_KB_READ,
        PERM_KB_CREATE,
        PERM_KB_UPDATE,
        PERM_PLAYBOOKS_READ,
        PERM_PLAYBOOKS_CREATE,
        PERM_PLAYBOOKS_UPDATE,
        PERM_JOBS_READ,
        PERM_JOBS_CANCEL,
        PERM_PIVOTS_READ,
        PERM_PIVOTS_MANAGE,
        PERM_SCANS_RUN,
        PERM_SCANS_READ,
    },
    "viewer": {
        PERM_PROJECT_READ,
        PERM_HOSTS_READ,
        PERM_CREDENTIALS_READ,
        PERM_FINDINGS_READ,
        PERM_NOTES_READ,
        PERM_LOOT_READ,
        PERM_NETWORK_READ,
        PERM_TOPOLOGY_READ,
        PERM_REPORTS_READ,
        PERM_TIMELINE_READ,
        PERM_SCOPES_READ,
        PERM_ATTACK_PATHS_READ,
        PERM_COMMAND_OUTPUTS_READ,
        PERM_CHECKLIST_READ,
        PERM_OBJECTIVES_READ,
        PERM_SEARCH_READ,
        PERM_KB_READ,
        PERM_PLAYBOOKS_READ,
        PERM_JOBS_READ,
        PERM_PIVOTS_READ,
        PERM_SCANS_READ,
    },
    "auditor": {
        PERM_PROJECT_READ,
        PERM_HOSTS_READ,
        PERM_FINDINGS_READ,
        PERM_NOTES_READ,
        PERM_LOOT_READ,
        PERM_NETWORK_READ,
        PERM_REPORTS_READ,
        PERM_REPORTS_EXPORT,
        PERM_TIMELINE_READ,
        PERM_ATTACK_PATHS_READ,
        PERM_COMMAND_OUTPUTS_READ,
        PERM_CHECKLIST_READ,
        PERM_OBJECTIVES_READ,
        PERM_SEARCH_READ,
        PERM_KB_READ,
        PERM_PLAYBOOKS_READ,
        PERM_JOBS_READ,
        PERM_PIVOTS_READ,
        PERM_SCANS_READ,
    },
}

PROJECT_ROLES = list(ROLE_PERMISSIONS.keys())


def get_permissions_for_role(role: str) -> set[str]:
    return ROLE_PERMISSIONS.get(role, set())


def get_membership(db: Session, project_id: str, user_id: str) -> models.ProjectMember | None:
    return (
        db.query(models.ProjectMember)
        .filter(
            models.ProjectMember.project_id == project_id,
            models.ProjectMember.user_id == user_id,
            models.ProjectMember.is_active,
        )
        .first()
    )


def add_project_owner(db: Session, project_id: str, user_id: str, created_by: str | None = None):
    """Add user as owner of a project (or upgrade existing membership)."""
    existing = get_membership(db, project_id, user_id)
    if existing:
        existing.role = MemberRole.OWNER
        existing.is_active = True
    else:
        member = models.ProjectMember(
            id=new_id("pm"),
            project_id=project_id,
            user_id=user_id,
            role=MemberRole.OWNER,
            created_at=ts_now(),
            created_by=created_by,
            is_active=True,
        )
        db.add(member)
