# RootNotes — Module Development Guide

## Overview

RootNotes supports drop-in backend and frontend modules. Drop a Python file in
`backend/app/plugins/modules/` and a JS file that calls `moduleRegistry.register()`
in the frontend — both are auto-loaded at startup.

---

## Backend module

### Minimal example

Create `backend/app/plugins/modules/my_plugin.py`:

```python
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.plugins.types import BackendModule
from app.core.deps import get_current_user
from app.database import get_db

router = APIRouter(prefix="/api/my-plugin", tags=["my-plugin"])

@router.get("/hello")
def hello(user=Depends(get_current_user)):
    return {"hello": user.username}

MODULE = BackendModule(
    name="my_plugin",
    version="1.0.0",
    description="My custom plugin",
    router=router,
)
```

The loader discovers `MODULE` automatically and registers its router with the app.

### Scan parser example

To add a new scan format (e.g. Masscan JSON):

```python
import json

def parse_masscan_json(content: str) -> list[dict]:
    data = json.loads(content)
    hosts = []
    for entry in data:
        hosts.append({
            "ip": entry["ip"],
            "hostname": "",
            "os": "Unknown",
            "ports": [
                {"port": p["port"], "proto": p["proto"], "state": "open", "service": p.get("reason", "")}
                for p in entry.get("ports", [])
            ],
        })
    return hosts

MODULE = BackendModule(
    name="masscan_parser",
    version="1.0.0",
    description="Masscan JSON scan parser",
    scan_parsers={"masscan": parse_masscan_json},
)
```

The topology builder picks up `scan_parsers` automatically — the key becomes a valid
`source_type` for `POST /api/projects/{pid}/topology/preview`.

### BackendModule contract

```python
@dataclass
class BackendModule:
    name: str
    version: str
    description: str = ""
    enabled: bool = True
    router: APIRouter | None = None
    scan_parsers: dict[str, Callable] = field(default_factory=dict)
    export_contributors: list[Callable] = field(default_factory=list)
    report_contributors: list[Callable] = field(default_factory=list)
    search_providers: list[Callable] = field(default_factory=list)
    startup_hooks: list[Callable] = field(default_factory=list)
    shutdown_hooks: list[Callable] = field(default_factory=list)
```

### Checking registered modules

```
GET /api/modules
```

```json
{
  "modules": [
    {
      "name": "my_plugin",
      "version": "1.0.0",
      "description": "My custom plugin",
      "enabled": true,
      "has_router": true,
      "scan_parsers": []
    }
  ]
}
```

---

## Frontend module

### Minimal example — adds a sidebar item and a host tab

```js
import { moduleRegistry } from './features/plugins/registry.js';
import MyHostTab from './components/MyHostTab.jsx';

moduleRegistry.register({
  id: 'my-plugin',
  title: 'My Plugin',
  version: '1.0.0',
  description: 'Adds a custom host tab',
  enabled: true,

  menuItems: [{
    id: 'my-menu',
    label: 'My Plugin',
    icon: 'target',
    tab: 'my-plugin',
  }],

  hostTabs: [{
    id: 'my-tab',
    label: 'My Tab',
    component: MyHostTab,
  }],
});
```

### All extension points

| Field              | Type                              | Where it appears                       |
|--------------------|-----------------------------------|----------------------------------------|
| `menuItems`        | `[{ id, label, icon, tab }]`      | Sidebar navigation                     |
| `routes`           | `[{ path, component }]`           | React Router routes                    |
| `projectTabs`      | `[{ id, label, component }]`      | Tabs on the project page               |
| `hostTabs`         | `[{ id, label, component }]`      | Tabs inside the host detail card       |
| `networkTabs`      | `[{ id, label, component }]`      | Tabs in the network node panel         |
| `reportSections`   | `[{ id, label, component }]`      | Extra sections in report generation    |
| `importers`        | `[{ id, label, accept, component }]` | Import UI entries                   |
| `dashboardWidgets` | `[{ id, component }]`             | Dashboard widget slots                 |
| `actions.hosts`    | `[{ id, label, handler }]`        | Context actions on host rows           |
| `actions.findings` | `[{ id, label, handler }]`        | Context actions on finding rows        |
| `actions.creds`    | `[{ id, label, handler }]`        | Context actions on credential rows     |
| `actions.networkNodes` | `[{ id, label, handler }]`    | Context actions on topology nodes      |

### Reading aggregated extension points

```js
import { moduleRegistry } from './features/plugins/registry.js';

const hostTabs   = moduleRegistry.getHostTabs();
const menuItems  = moduleRegistry.getMenuItems();
const importers  = moduleRegistry.getImporters();
```

---

## File placement

```
backend/app/plugins/modules/   ← drop .py files here (auto-loaded)
frontend/src/plugins/          ← import and call moduleRegistry.register() in index.js
```

Backend modules are discovered via `pkgutil.iter_modules` on startup.
Frontend modules must be explicitly imported (no auto-discovery in the browser).
