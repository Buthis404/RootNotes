# RootNotes — Architecture

## Overview

RootNotes uses a domain-oriented architecture.

- backend is split by API domain under `routers/`
- shared runtime logic lives in `core/`
- extensibility lives in `plugins/`
- frontend is organized by feature views and shared components

The current direction of the system is no longer just CRUD over pentest data.
It is evolving into an orchestration-oriented workspace where jobs, connectors,
topology, credentials, and evidence all participate in one operational model.

## Backend Structure

```text
backend/app/
  main.py                 ← app assembly, middleware, startup hooks, WS, router wiring
  database.py             ← SQLAlchemy engine and session factory
  models/                 ← ORM model packages by domain
  schemas/                ← Pydantic schema packages by domain
  ws.py                   ← WebSocket connection manager

  core/
    config.py             ← environment and runtime settings
    security.py           ← JWT and password hashing
    deps.py               ← FastAPI dependencies
    events.py             ← timeline + WebSocket broadcast helpers
    utils.py              ← IDs, normalization, scope helpers
    layout.py             ← topology layout engine
    job_tracker.py        ← central job lifecycle helpers
    connectors.py         ← normalized connector contract
    ssh_exec.py           ← remote SSH execution helper
    permissions.py        ← project RBAC model
    access.py             ← access checks by project or object

  routers/
    auth.py               ← auth and profile endpoints
    admin.py              ← admin user management
    projects.py           ← projects CRUD
    members.py            ← project membership and role management
    hosts.py              ← hosts CRUD and bulk host import
    creds.py              ← credentials CRUD
    notes.py              ← notes CRUD, attachments, version conflict handling
    findings.py           ← findings CRUD
    loots.py              ← loot CRUD and file uploads
    scopes.py             ← scope tracking
    checklist.py          ← project checklist
    timeline.py           ← project timeline
    objectives.py         ← objectives tracking
    activities.py         ← host activity log
    attack_paths.py       ← attack paths and steps
    cred_host_notes.py    ← host-specific credential annotations
    networks.py           ← network map CRUD
    network_map.py        ← node, edge, region mutations
    topology.py           ← topology preview, apply, rebuild-layout, auto-build
    scans.py              ← Nmap, Nuclei, NetExec orchestration
    attacker_exec.py      ← remote attacker-host execution
    bulk_actions.py       ← bulk execution and credential validation workflows
    jobs.py               ← job center API
    webhooks.py           ← event ingestion into project state
    c2.py                 ← C2 integration CRUD and sync
    search.py             ← global search
    templates.py          ← finding/snippet template APIs
    project_templates.py  ← starter project blueprints
    import_export.py      ← project import/export and parser-backed imports
    export.py             ← CSV export endpoints
    system_modules.py     ← module and attacker-SSH admin controls

  services/
    host_service.py       ← domain helper service
    project_service.py    ← domain helper service

  plugins/
    types.py              ← BackendModule contract
    registry.py           ← module registry + connector discovery
    loader.py             ← builtin registration + plugin auto-load
    state.py              ← persisted module state and attacker target config
    modules/              ← drop-in backend plugin files
```

## Frontend Structure

```text
frontend/src/
  App.jsx                 ← route/view switcher
  main.jsx                ← frontend bootstrap
  app/
    AppChrome.jsx         ← primary shell, navigation, and project bootstrap
  constants.js            ← tabs, enums, default data, snippets

  api/
    client.js             ← req(), upload(), download()
    index.js              ← full API surface
  api.js                  ← backward-compatible re-export

  components/
    TopologyBuilderModal.jsx
    SearchModal.jsx
    ImportModal.jsx
    MdEditor.jsx
    MdPreview.jsx
    NmapParser.jsx
    NessusParser.jsx
    BloodHoundParser.jsx
    AttackVectorAnalyzer.jsx
    ...shared UI components

  views/
    ProjectsView.jsx
    NotesView.jsx
    HostsView.jsx
    CredsView.jsx
    FindingsView.jsx
    NetworkView.jsx
    AttackPathView.jsx
    LootView.jsx
    ScopeView.jsx
    ChecklistView.jsx
    TimelineView.jsx
    ObjectivesView.jsx
    ScansView.jsx
    JobsView.jsx
    ReportView.jsx
    AdminView.jsx
    SystemModulesView.jsx
    MembersPanel.jsx
    UserSettingsView.jsx
    CheatsheetView.jsx
    LoginView.jsx

  store/
    useProjectStore.js    ← shared project-domain state
    useAuthStore.js       ← auth-related local state helper

  hooks/
    useSync.js            ← WebSocket subscription logic
    useColumnResize.js    ← table resizing behavior

  context/
    ProjectPermissions.jsx ← project permission context

  features/
    plugins/
      registry.js         ← frontend module registry
      types.js            ← extension point contract

  utils/
    hostMeta.js           ← host type and role heuristics
    parsers.js            ← parsing helpers
```

## Current Architectural Themes

## 1. Domain-first API layout

Each main pentest entity or workflow has its own router.

This keeps the backend easy to extend without concentrating all business logic
in `main.py`.

## 2. Jobs as orchestration backbone

`core/job_tracker.py` and `routers/jobs.py` now form a shared orchestration base.

Each job stores:

- type
- status
- title
- target
- command
- output and error output
- created_by
- connector metadata
- operation metadata
- related entity metadata
- structured result JSON

This makes jobs the current common lifecycle wrapper for:

- scans
- attacker execution
- bulk actions
- C2 sync
- topology operations

Current state:

- jobs are tracked centrally and executed through a bounded internal worker pool by default
- Redis/`arq` worker mode exists as an optional backend for heavier queued execution
- playbooks support ordered steps, DAG-aware run visualization, retry/precondition metadata, and `c2:exec` integration

## 3. Connectors as normalized tool contract

`core/connectors.py` defines the normalized connector contract.

Connectors are exposed through backend modules and aggregated by the plugin registry.

Current builtin connector categories:

- `scan`
- `execution`
- `topology`
- `c2`

The registry exposes:

- module metadata
- scan parsers
- connector inventory

This is the foundation for evolving from isolated tool endpoints to a unified orchestration layer.

## 4. Plugins as extension boundary

The plugin system currently supports:

- backend module metadata
- backend routers
- scan parsers
- connector definitions
- frontend extension points

This is the right architectural boundary for adding new tool families without contaminating core domains.

## 5a. AI as integrated operational assistant

`core/ai_manager.py` manages AI provider configuration at the project level.

Supported provider types:

- `openai` — OpenAI-compatible endpoint (OpenAI, Azure, local vLLM)
- `anthropic` — Anthropic Claude direct API
- `ollama` — local Ollama server
- `litellm` — LiteLLM proxy (any model string; added in v0.9.0)

The AI manager stores provider config in `global_settings`, handles per-project
overrides, and exposes a unified async `call()` interface that the AI chat router
and playbook AI steps consume. Unknown providers fall back gracefully; function-
calling errors fall back to a no-tools call before surfacing to the user.

## 5. Topology as operational graph

Topology is no longer just a visual map.

The backend topology subsystem now includes:

- scan preview and apply
- layout rebuild
- auto-build from project hosts
- smart gateway and subnet inference
- inferred edge confidence and reason metadata
- job tracking for topology operations

The frontend network view already combines:

- network map editing
- topology builder entrypoints
- overlays for findings, creds, objectives, and attack steps
- host-centric interaction inside the map

Current limitation:

- topology is still mostly host-centric
- subnet, route, trust-zone, and reachability concepts are not first-class entities yet

## API Surface Summary

Core discovery endpoints:

- `GET /api/modules`
- `GET /api/connectors`

Job center:

- `GET /api/projects/{pid}/jobs`
- `GET /api/projects/{pid}/jobs/{job_id}`
- `PATCH /api/projects/{pid}/jobs/{job_id}/cancel`
- `DELETE /api/projects/{pid}/jobs/{job_id}`

Topology:

- `POST /api/projects/{pid}/topology/preview`
- `POST /api/projects/{pid}/topology/apply`
- `POST /api/projects/{pid}/topology/rebuild-layout`
- `POST /api/projects/{pid}/topology/auto-build`
- `GET /api/projects/{pid}/topology`
- `GET /api/projects/{pid}/topology/sources`

Execution and orchestration:

- `POST /api/projects/{pid}/scans/nmap`
- `POST /api/projects/{pid}/scans/nuclei`
- `POST /api/projects/{pid}/scans/cme`
- `POST /api/projects/{pid}/attacker-exec`
- `POST /api/projects/{pid}/bulk-exec`
- `POST /api/projects/{pid}/creds/{cred_id}/validate`

C2 and ingestion:

- `GET/POST/PATCH/DELETE /api/admin/c2/*`
- `POST /api/webhooks/{token}`

## Data Model Notes

Schema is managed through Alembic migrations under `backend/alembic/`.

This means:

- schema history is explicit and versioned
- container startup applies migrations automatically before serving traffic
- additive and data-affecting schema changes can be tracked in release notes

## WebSocket Model

Project-scoped WebSocket rooms are still the main live-state synchronization mechanism.

Message shape remains:

```json
{ "pid": "...", "entity": "...", "action": "...", "data": { ... } }
```

The same broadcast path is used by CRUD entities and orchestration entities such as jobs.

## Architectural Risks and Constraints

## 1. Frontend view files — major views decomposed in v0.9.0

The largest monolithic views have been split:

- `NetworkView` (2 320 → 295 lines) → `NetworkCanvas`, `NetworkInspector`, `NetworkToolbar`
- `PlaybooksView` (2 342 → 663 lines) → DAG visualisation, step editor, playbook list
- `ScansView` → C2 panel, webhook form, pivot components extracted

The frontend now matches the modular backend architecture.
Remaining growth should keep to this pattern: one file per coherent visual concern.

## 2. Orchestration is centralized conceptually, but not yet physically

The code now has a shared jobs layer and a shared connector contract, but orchestration logic is still distributed across routers.

That is fine for the current phase, but the next iteration should avoid re-embedding job lifecycle and tool semantics in every domain router.

## 3. Topology still needs richer graph semantics

The system already stores operationally useful edge metadata such as confidence and reason.

The next architectural step is not more layout work.
It is stronger graph semantics:

- segment identity
- reachability
- route state
- verification state
- attacker infrastructure modeling

## Recommended Implementation Stages

## Stage 1. Keep architecture docs aligned with real code

Work:

- update docs whenever routers or subsystems are added
- treat `jobs`, `connectors`, and `topology` as first-class architecture topics

Why:

- the project has already outgrown the original simplified architecture document

## Stage 2. Promote jobs into full orchestration backbone

Work:

- route all long-running operations through jobs
- add retry and rerun semantics
- define terminal and non-terminal lifecycle transitions centrally
- enrich job-to-entity linkage

Why:

- this builds on architecture already present in code

## Stage 3. Promote connectors into a real orchestration catalog

Work:

- use connector metadata consistently across scans, execution, and ingestion
- standardize what each connector declares:
  - operations
  - outputs
  - created entities
  - evidence behavior

Why:

- this makes tool growth modular instead of router-specific

## Stage 4. Evolve topology into the operational graph

Work:

- ingest more sources into topology
- persist richer edge and node semantics
- connect jobs, attack path, creds, and findings into the graph
- add route and reachability semantics

Why:

- topology is the natural visual center of the platform

## Stage 5. Deepen playbooks and pipelines

Work:

- continue consolidating playbook execution on top of jobs and connectors
- deepen DAG semantics, retries, preconditions, and live run introspection
- keep step templates / packs / scheduled runs aligned with the same execution model

Why:

- jobs and connectors should stabilize first

## Stage 6. Decompose large frontend feature views ✓ done in v0.9.0

Completed: `NetworkView`, `PlaybooksView`, and `ScansView` decomposed into
focused modules. Each view now has a clear split between canvas/list, inspector,
and action panels.

## Current Best Direction

The most important architectural takeaway is this:

RootNotes should now be developed as an orchestration-centric platform.

That means the core long-term relationship is:

`connectors -> jobs -> topology/graph -> evidence/findings/reporting`

not just:

`forms -> CRUD tables -> export`

The current architecture is already close enough to support that direction.
The next work should deepen and unify the pieces that now exist.
