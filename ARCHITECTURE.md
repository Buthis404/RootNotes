# RootNotes — Architecture

## Overview

RootNotes uses a modular architecture where each domain has its own files.
Main files are assembly points, not business logic containers.

---

## Backend Structure

```
backend/app/
  main.py              ← App assembly: routers, middleware, WS, lifespan
  database.py          ← SQLAlchemy engine and session factory
  models.py            ← SQLAlchemy ORM models
  schemas.py           ← Pydantic request/response schemas
  ws.py                ← WebSocket ConnectionManager

  core/
    config.py          ← Environment variables (JWT_SECRET, UPLOAD_ROOT, etc.)
    security.py        ← JWT encode/decode, password hashing
    deps.py            ← FastAPI dependencies: get_current_user, require_admin
    events.py          ← log_event(), bcast() — timeline and WebSocket helpers
    utils.py           ← new_id(), normalize_domain(), scope sync helpers

  routers/             ← One file per domain, each exports an APIRouter
    auth.py            → /api/auth/*
    admin.py           → /api/admin/*
    projects.py        → /api/projects/*
    hosts.py           → /api/hosts/*
    creds.py           → /api/creds/*
    notes.py           → /api/notes/*, /attachments/*
    networks.py        → /api/networks/*
    findings.py        → /api/findings/*
    checklist.py       → /api/checklist/*
    timeline.py        → /api/timeline
    objectives.py      → /api/objectives/*
    activities.py      → /api/host-activities/*
    attack_paths.py    → /api/attack-paths/*, /api/attack-steps/*
    loots.py           → /api/loots/*
    scopes.py          → /api/scopes/*
    cred_host_notes.py → /api/cred-host-notes/*
    search.py          → /api/search
    templates.py       → /api/finding-templates/*, /api/snippets/*
    import_export.py   → /api/export/*, /api/import_project, /api/import/*
    topology.py        → /api/projects/{pid}/topology/*

  plugins/
    types.py           ← BackendModule dataclass (module contract)
    registry.py        ← ModuleRegistry singleton
    loader.py          ← Auto-discover and register modules on startup
    modules/           ← Drop custom modules here (auto-loaded)
```

### Adding a new backend route domain

1. Create `backend/app/routers/my_domain.py`
2. Define `router = APIRouter(prefix="/api/my-domain", tags=["my-domain"])`
3. Add your route handlers
4. In `main.py`, add:
   ```python
   from .routers import my_domain
   app.include_router(my_domain.router)
   ```

---

## Frontend Structure

```
frontend/src/
  api.js                   ← Backward-compat re-export from api/index.js
  api/
    client.js              ← Base req(), upload(), download() functions
    index.js               ← All API methods (full api object)

  features/
    plugins/
      registry.js          ← Frontend ModuleRegistry singleton
      types.js             ← Module contract definition

  components/
    TopologyBuilderModal.jsx  ← Topology builder UI (preview/apply workflow)
    ... (existing components)

  views/                   ← One file per major feature view
  hooks/                   ← useSync.js (WebSocket), useColumnResize.js
  utils/                   ← hostMeta.js, parsers.js
  constants.js
```

### Importing API in new code

```js
// Preferred — direct import
import { api } from '../api/index.js';

// Legacy — still works
import { api } from '../api.js';
```

---

## Module Registry

### Backend

The `ModuleRegistry` (singleton in `plugins/registry.py`) holds all registered `BackendModule` instances.

```python
from app.plugins.registry import registry
from app.plugins.types import BackendModule
from fastapi import APIRouter

my_router = APIRouter(prefix="/api/my-plugin")

@my_router.get("/hello")
def hello():
    return {"hello": "world"}

MODULE = BackendModule(
    name="my_plugin",
    version="1.0.0",
    description="My custom plugin",
    router=my_router,
    scan_parsers={"my_format": parse_my_format},
)
```

Place the file in `backend/app/plugins/modules/my_plugin.py` — it will be auto-loaded.

### Frontend

The `moduleRegistry` (singleton in `features/plugins/registry.js`) aggregates UI extension points.

```js
import { moduleRegistry } from '../features/plugins/registry.js';

moduleRegistry.register({
  id: 'my-plugin',
  title: 'My Plugin',
  version: '1.0.0',
  description: 'Adds a custom host tab',
  enabled: true,
  hostTabs: [{
    id: 'my-tab',
    label: 'My Tab',
    component: MyTabComponent,
  }],
  menuItems: [{
    id: 'my-menu',
    label: 'My Plugin',
    icon: 'target',
    tab: 'my-plugin',
  }],
});
```

### /api/modules

`GET /api/modules` returns the list of all registered backend modules with their status.

```json
{
  "modules": [
    {
      "name": "topology",
      "version": "1.0.0",
      "description": "...",
      "enabled": true,
      "has_router": false,
      "scan_parsers": []
    }
  ]
}
```

---

## Topology Builder

Automatically constructs network topology from scan files.

### API

```
POST /api/projects/{pid}/topology/preview        — analyse scan, return diff
POST /api/projects/{pid}/topology/apply          — apply confirmed diff
POST /api/projects/{pid}/topology/rebuild-layout — recompute node positions
GET  /api/projects/{pid}/topology               — topology summary
GET  /api/projects/{pid}/topology/sources       — supported source types
```

### Preview request (multipart/form-data)

```
file:                   <scan file>
source_type:            nmap
keep_manual_positions:  true
create_links:           true
update_existing_hosts:  true
```

### Preview response

```json
{
  "new_hosts":      [{ "ip": "10.0.0.1", "hostname": "", "ports": [...], "is_new": true }],
  "updated_hosts":  [{ "ip": "10.0.0.2", "existing_id": "hstXXX", "changes": {"ports_added": ["22/tcp"]} }],
  "new_links":      [{ "source_ip": "10.0.0.1", "target_ip": "10.0.0.2", "link_type": "same_subnet" }],
  "conflicts":      [],
  "summary":        "Found 5 hosts: 3 new, 2 updates, 4 links"
}
```

### Supported scan formats

| Format     | Parser              | Notes                        |
|------------|---------------------|------------------------------|
| Nmap XML   | `parse_nmap_xml()`  | Use `-oX output.xml`         |

### Manual node positions

Nodes with `manually_positioned: true` in `nodes_json` are never moved by the layout algorithm when `keep_manual_positions=true`.

---

## Database

Schema is managed via idempotent `ALTER TABLE ... IF NOT EXISTS` statements in `main.py` — no Alembic.

To add a new column:
```python
conn.execute(text("ALTER TABLE my_table ADD COLUMN IF NOT EXISTS my_col TEXT NOT NULL DEFAULT ''"))
```

---

## WebSocket

`/ws/{pid}?token=<jwt>` — real-time sync scoped to a project room.

Messages follow `{ pid, entity, action, data }` pattern.
The `bcast(pid, entity, action, data)` helper in `core/events.py` is used by all routers.

---

## Compatibility

- All original API endpoints preserved at identical paths
- Export/import ZIP format unchanged
- Database schema extended non-destructively (IF NOT EXISTS)
- Existing network map JSONB format unchanged
- Frontend `api.js` re-exports from `api/index.js` — no breaking changes
