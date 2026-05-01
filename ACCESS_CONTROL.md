# RootNotes — Access Control

## Overview

RootNotes uses a two-level access model:

1. **Global role** (`User.role`) - system-wide permissions
2. **Project role** (`ProjectMember.role`) - permissions within a specific project

---

## Global Roles

| Role | Description |
|------|----------|
| `admin` | Super admin: can see all projects and bypasses project-level checks |
| `user` | Regular user: can only see projects where they are a member |
| `viewer` | Legacy read-only account: limited to GET requests at the middleware level |

---

## Project Member Roles

| Role | Description |
|------|----------|
| `owner` | Full access, member management, project deletion, and ownership transfer |
| `admin` | Full operational access plus member management (except owner actions) |
| `editor` | CRUD access to all project data, without member management |
| `operator` | Operational actions: hosts, findings, activities, with limited editing |
| `viewer` | Read-only access to all project data, without secrets |
| `auditor` | Read access to reports, timeline, and findings; no secrets and no editing |

---

## Permission Matrix (Key Permissions)

| Permission | owner | admin | editor | operator | viewer | auditor |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| project.read | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| project.update | ✓ | ✓ | — | — | — | — |
| project.delete | ✓ | — | — | — | — | — |
| project.manage_members | ✓ | ✓ | — | — | — | — |
| project.export | ✓ | ✓ | ✓ | — | — | — |
| project.import | ✓ | ✓ | ✓ | — | — | — |
| project.transfer_ownership | ✓ | — | — | — | — | — |
| hosts.read | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| hosts.create/update/delete | ✓ | ✓ | ✓ | create/update | — | — |
| credentials.read | ✓ | ✓ | ✓ | ✓ | ✓ | — |
| **credentials.read_secret** | ✓ | ✓ | — | — | — | — |
| credentials.create/update | ✓ | ✓ | ✓ | ✓ | — | — |
| findings.read | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| findings.create/update/delete | ✓ | ✓ | ✓ | create/update | — | — |
| network.manage_nodes/links | ✓ | ✓ | ✓ | — | — | — |
| topology.apply | ✓ | ✓ | ✓ | — | — | — |
| reports.export | ✓ | ✓ | — | — | — | ✓ |

The full matrix is defined in `backend/app/core/permissions.py` (`ROLE_PERMISSIONS`).

---

## API

### Member Management

```
GET    /api/projects/{pid}/members              - list members
POST   /api/projects/{pid}/members              - add a member
PATCH  /api/projects/{pid}/members/{uid}        - change a role
DELETE /api/projects/{pid}/members/{uid}        - remove a member
POST   /api/projects/{pid}/transfer-ownership   - transfer ownership
GET    /api/projects/{pid}/permissions/me       - get my project permissions
```

**Add a member:**
```json
{ "user_id": "u...", "role": "editor" }
```

**Change a role:**
```json
{ "role": "viewer" }
```

**Current user permissions:**
```json
{
  "project_id": "p...",
  "role": "editor",
  "permissions": ["project.read", "hosts.read", "hosts.create", ...],
  "is_super_admin": false
}
```

---

## Security Rules

- No IDOR: a user cannot access objects from another project by direct ID
- `GET /api/projects` returns only projects where the user is a member
- `credentials.secret` is returned as an empty string without the `credentials.read_secret` permission
- Export requires `project.export`; import requires `project.import`
- WebSocket (`/ws/{pid}`) validates membership before connecting
- When a project is created, the creator automatically becomes `owner`
- When a new project is imported, the current user becomes `owner`
- The last `owner` of a project cannot be removed
- Global `admin` bypasses all project-level checks

---

## Existing Data Migration

On startup, the backend automatically:
1. Creates the `project_members` table
2. Assigns the first `admin` user as `owner` for every project that does not yet have one

Indexes:
- `idx_pm_project_id` - fast project lookup
- `idx_pm_user_id` - fast user lookup
- `idx_pm_project_user` - unique constraint

---

## Manual Testing

```bash
# 1. Create user bob
curl -X POST /api/admin/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"username":"bob","password":"pass","role":"user"}'

# 2. Bob does not see admin projects
curl /api/projects -H "Authorization: Bearer $BOB_TOKEN"
# → []

# 3. Admin adds Bob as viewer
curl -X POST /api/projects/{pid}/members \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"user_id":"<bob_id>","role":"viewer"}'

# 4. Bob sees the project but cannot create a host
curl -X POST /api/hosts \
  -H "Authorization: Bearer $BOB_TOKEN" \
  -d '{"pid":"...","ip":"10.0.0.1",...}'
# → 403 Insufficient permissions

# 5. Bob as viewer cannot see secrets
curl /api/creds?pid=... -H "Authorization: Bearer $BOB_TOKEN"
# → secret: ""

# 6. Check permissions
curl /api/projects/{pid}/permissions/me \
  -H "Authorization: Bearer $BOB_TOKEN"
```
