# RootNotes — Changelog

## Unreleased

### Smart Build — SB6 Service-graph edges (opt-in)

Two heuristic rules for client→service dependency edges:

1. **Web → DB** — host with role `web` (or open 80/443/8080/8443) draws a `service_dep` edge to every host with role `database` (or open 1433/3306/5432/1521) in the same `/24`
2. **LDAP-client → DC** — every domain-joined non-DC host draws a `service_dep` edge to a DC of the same domain. Redundant when `include_domain_edges=true` (P4 already draws the reverse `domain_member` edge — dedup blocks it), but useful when domain edges are disabled

Backend:
- `SmartBuildRequest.include_service_graph: bool = False` (default OFF — inference, not observation)
- New block in `_run_smart_build` between P4 and P5
- Edge fields: `type=service_dep`, `source=service_inference`, `confidence=0.5`, `state=inferred`, `verified=false`, `style=dashed`

Frontend:
- `NetworkView.jsx` edge style for `service_dep`: grey thin dashed (`#6a7180`, `2 4` dasharray), no animation — deliberately quieter than access/lateral so the map stays readable

Tested on synthetic project `p3e291272` (SB6-test): web→db edge correctly produced, LDAP edges blocked by P4 dedup as expected.

---

### Smart Build — SB4 Edge MITRE / noise / kill-chain tagging

Action-class edges now carry three metadata fields in `extra_json`:
- `mitre_techniques` — MITRE ATT&CK IDs (e.g. `["T1078"]`)
- `noise_level` — `low` / `med` / `high` (OPSEC noise)
- `kill_chain_stage` — `lateral_movement` / `execution` / `command_and_control` / etc.

Classification by source:
| Source | MITRE | Noise | Stage |
|--------|-------|-------|-------|
| `cred_validation` | T1078 | med | lateral_movement |
| `bulk_exec` | T1059 | high | execution |
| `host_activity` (c2) | T1071 | low | command_and_control |
| `host_activity` (lateral) | T1021 | med | lateral_movement |
| `host_activity` (postex) | T1059 | high | execution |
| `host_activity` (other) | T1059 | med | execution |
| `pivot_observation` | T1090 | low | command_and_control |

Inference sources (`auto` subnet/domain_member, `scope_via`, `internet_facing`, `bloodhound`) are NOT tagged — they describe topology, not actions.

Backend:
- New `_edge_action_tags(source, edge_type, activity_type)` helper in `topology.py`
- Three `_add_edge` call sites (P1 cred_validation, P2 bulk_exec, P3 host_activity) merge the result into `edge_data`
- One-time backfill loop after `manual_edges = [...]` enriches pre-SB4 host_activity / pivot edges that survived the auto filter

Frontend:
- `NetworkView.jsx` side panel: three new chips next to confidence for any edge carrying these fields — purple MITRE list, colour-coded noise (green/amber/red), blue kill-chain stage. Tooltip on hover.

---

### Smart Build — SB3 Tier-0/1/2 host classification

Smart Build now classifies every host into one of three AD tiers and surfaces it both as a node tag and a coloured chip on the network map.

- **Tier 0** — domain controllers, DA/EA-equivalent hosts (role=`domain_controller`, tags `dc` / `da` / `ea` / `bh:dc` / `bh:da-member`)
- **Tier 1** — admin-power servers: targets of admin-class edges (`smb_admin`, `admin_to`, `local_admin`, `dcsync`, ACL writes `generic_all`/`write_dacl`/`generic_write`/`write_owner`/`ext_rights`, `allowed_to_delegate`); hosts with `HostActivity.technique` starting with `T1003` (LSASS / SAM / NTDS credential dumping); hosts tagged `bh:admin`
- **Tier 2** — workstations / everything else

Backend changes:
- `SmartBuildRequest.include_tier_zones: bool = True` (default on)
- After all edges are built, `_run_smart_build` iterates over `all_hosts` and writes `node.extra_json.tier` (0 / 1 / 2) plus a `tier:N` tag (replacing any prior `tier:*` tag — idempotent across rebuilds)
- Result now contains `tier_counts: {tier_0, tier_1, tier_2}`

Frontend changes (`NetworkView.jsx`):
- T0 / T1 coloured chips in the top-right corner of each node (red `#e8574a` / amber `#f09a3a`)
- T2 nodes are intentionally silent — chip is only drawn for T0/T1 to keep the map readable

---

### Fix — Smart Build position stability

Repeating Smart Build no longer scatters the network map.

- New `SmartBuildRequest.preserve_positions: bool = True` (default true)
- When true, any node that already has `x`/`y` keeps its position through
  rebuild — covers both prior auto-positioned and manually positioned nodes
- Three blocks that previously moved nodes on every build now respect the flag:
  1. The `compute_layout` apply loop in `_run_smart_build`
  2. Transit/region overlay (`_place_between_regions`, `_place_on_region_edge`)
  3. Attacker uplink relative to entry-region anchor
- `manually_positioned=True` nodes remain protected via `keep_manual_positions`
- To force a full re-layout, either call `POST /topology/rebuild-layout`
  or pass `preserve_positions: false` to Smart Build

---

### Smart Build — SB2 BloodHound edges expansion

BloodHound importer (`import_bloodhound.py`) gained three new edge types and three node-tag enrichments. Smart Build preserves them through its `manual_edges` filter (any edge with `source != "auto"`), so they survive rebuild without further pipeline changes.

#### New edge types
- `can_rdp` — `CanRDP` principals (computers in the top-level CanRDP key), `confidence=0.8`, `state="inferred"`
- `allowed_to_delegate` — constrained-delegation principals → target computer, `confidence=0.85`, `state="inferred"`
- `trust` — domain-trust edges between DCs of different domains, parsed from `*_domains.json` `Trusts[].TrustType` / `TrustDirection`, `confidence=0.95`, `verified=true`; label encodes type (`ParentChild` / `CrossLink` / `Forest` / `External`) and direction (`Inbound` / `Outbound` / `Bidirectional`)

#### Node-tag enrichment (step 6.5)
- `bh:dc` — domain controllers (host.role=domain_controller or `dc` in tags)
- `bh:admin` — hosts that are source of any `smb_admin` or ACL edge (admin power principals)
- `bh:da-member` — hosts whose SID is a member of DA-equivalent groups

Tags are written to `host.tags` and propagate to `node.tags` on the next Smart Build / Auto-Build (which copies host tags into node tags).

#### Stats fields added
`can_rdp_edges`, `allowed_to_delegate_edges`, `trust_edges`, `bh_dc_tagged`, `bh_admin_tagged`, `bh_da_member_tagged`.

#### Internals
- `add_edge` helper now returns `bool` for dedup-aware counting
- New `_add_host_tag` helper for idempotent tag insertion

---

### Smart Build — L1 stable edge IDs

- New `stable_edge_id(from_nid, to_nid, source, kind)` helper in `core/utils.py` — SHA1-derived deterministic edge id (format `edg<12hex>`)
- `_run_smart_build._add_edge` and the legacy `topology/apply` + `topology/auto-build` edge writers switched from random `new_id("edg")` to `stable_edge_id`
- `kind` priority: first `access_role` if present, otherwise `type` — same `(from, to, source)` pair can carry several access edges (ssh / winrm / local_admin) as separate stable ids
- Pivot observation edges in `pivots.py` are now keyed by `pivot_observation_id` so the same observation always yields the same edge id across re-syncs
- Manual edges created from UI (`network_map.py`, `bulk_actions.py`) still use random ids — they are inserted once and never regenerated

Effect: UI state (selection, hover, manual node position annotations) keyed by edge id survives Smart Build / Auto-Build / Pivot Sync rebuilds.

---

## v0.2.2 — 2026-05-14

### Smart Build — Access graph deepening

#### Multi-hop session routing (P11)
- Sessions in pivot-only networks now render as the real chain `attacker → entry-gw → pivot → target` instead of a star from the attacker
- For each `HostActivity` (exec/postex/lateral/c2, status=done) ordered by `ts ASC`, the edge source is resolved in priority order:
  1. Earliest existing session in the same scope becomes the local pivot for subsequent ones
  2. `scope.via_host_id` (explicit pivot)
  3. Auto-junction host (router/VPN-GW) in the entry scope, discovered by role/tag/keyword
  4. Direct from attacker (fallback)
- Applies to all activity types, not only c2
- Routing reason is recorded in `edge.reason` ("via earlier session on …", "via scope.via_host …", "via auto-detected junction", "direct from attacker")

#### Pivot ↔ Scope automation
- Creating a `PivotObservation` (UI Add Pivot, PATCH update, or SSH collector) with a non-empty `route_cidr` auto-creates or refreshes a `Scope` with `value=<CIDR>`, `via_host_id=<pivot_host_id>`, `description="auto: via pivot <hid>"`
- Idempotent: an existing scope with the same CIDR only gets `via_host_id` set when it was previously empty (manually configured scopes are preserved)
- On pivot deletion: if the deleted pivot was the last one for the `(CIDR, host)` pair and the scope description still starts with `auto: via pivot`, the scope is removed automatically

#### Pivot-only scope regions and traffic isolation
- `infer_links_smart` gained an `isolated_subnets` parameter — inter-subnet LAN gateway↔gateway edges are skipped for any scope with `via_host_id` (connectivity is only through the pivot, never through the scope's own local gateway)
- Pivot-only scope regions get an orange fill (`#f09a3a` / `#f09a3a18`), `zone_type=scope_pivot`, and label `<desc> (via <pivot-hostname>)`
- Existing regions are refreshed in place when a scope is reclassified (user geometry is preserved; color/zone_type/via_host_id sync to current state)
- Hosts inside pivot regions inherit `node.zone_type=scope_pivot` and render the orange zone badge in the UI

#### L2/L3 — dedup and multi-homed hosts
- L2: P3 host_activity skips an edge when P1 cred_validation already drew one for the same `(attacker, target, access_role)` tuple (avoids double ssh edges)
- L3: `infer_links_smart` buckets each host into every subnet derived from `host.ips[]` — multi-homed gateways now appear in all of their subnets

#### L4/L5 observability and L6 dry-run
- L4: the smart-build API result returns `edges_by_source: {<source>: count}` — a breakdown across cred_validation / bulk_exec / host_activity / auto / scope_via / internet_facing
- L5: `meta_json.last_smart_build` (ISO timestamp) and `meta_json.last_smart_build_breakdown` are persisted on the network; the UI shows a toast with the breakdown after each build
- L6: `SmartBuildRequest.dry_run=True` runs the full pipeline and rolls back without commit/broadcast — useful for previewing the diff

#### P12 — Confidence decay
- Exponential confidence decay for bulk_exec edges (using `Job.finished_at`) and host_activity edges (using `HostActivity.ts`) with τ=14d (configurable via `confidence_decay_days`)
- Edges with `c < 0.4` are tagged `state="stale"` and rendered in grey dotted style so stale credential proofs no longer mislead operators

#### P13 — Internet-facing edges
- A virtual `vn-internet` node is auto-created whenever the project has hosts tagged `public / exposed / internet / internet-facing / edge / dmz-public`, or with non-RFC1918 IP addresses
- Edges of type `internet_facing` from that node to each public-facing host, rendered orange-red dashed
- Controlled by `SmartBuildRequest.include_internet_facing` (default true)

### Hosts — status validation fix
- The B6-scale WIP added a Pydantic validator for `Host.status` restricted to `{unknown, up, down, pwned, unreachable, attacker, access, compromised}`, but the frontend (`NODE_STATUS` in `constants.js`) emits `{unknown, alive, scanned, access, pwned, owned}` — creating a host or changing status from the UI returned 422 for any value outside the three-way intersection
- `_HOST_STATUSES` is expanded to the union of both sets plus back-compat aliases — all six dropdown statuses are now accepted by both `HostCreate` and `HostUpdate`

### B6 — Network data split (Alembic 002–005)
- Network data (nodes/edges/regions) moved out of JSON columns into dedicated tables `network_nodes`, `network_edges`, `network_regions` — removes the ≈1 MB serialized-JSON ceiling and the rewrite-the-whole-blob-per-change overhead
- New `backend/app/core/network_data.py` helpers (`get_nodes / get_edges / get_regions / replace_nodes / replace_edges / replace_regions`) — single read/write boundary for all routers
- Alembic migrations:
  - **002** creates the three tables, indexes, and back-fills them from the existing `regions_json/nodes_json/edges_json`
  - **003** adds FK / CASCADE constraints
  - **004** fixes `network_nodes.ports` / `services` column types (`ARRAY` instead of `JSONB`)
  - **005** converts `network_edges.confidence` from `INTEGER` to `DOUBLE PRECISION` (fixes the `int(0.9) → 0` rounding that made every inferred edge land at confidence 0) and adds `network_regions.extra_json`
- All routers (`hosts`, `creds`, `networks`, `network_map`, `topology`, `pivots`, `attack_paths`, `attack_graph`, `bulk_actions`, `attacker_exec`, `c2`, `findings`, `loots`, `notes`, `objectives`, `templates`, `project_templates`, `webhooks`, `system_modules`, `import_bloodhound`, `import_export`, `scans`, `search`) migrated to the helpers

### B0-1 — Alembic schema management
- Database schema management moved from ad-hoc `CREATE TABLE` / `ALTER TABLE` blocks in `main.py` to Alembic
- Base revision `001_full_schema.py` — snapshot of the current production schema for fresh installs
- Backend startup now runs `alembic upgrade head` automatically
- `alembic` and dependencies added to the backend Dockerfile

### P3 — FTS Search rewrite
- GIN functional indexes on `hosts / creds / notes / findings / kb_articles / custom_snippets`
- Search uses `websearch_to_tsquery` + `ts_rank_cd` for a single ranking across object types
- Snippets via `ts_headline` with `<b>` HTML markers for highlight
- Pagination through an `offset` query parameter plus a "Load More" button in the frontend
- `kb` and `snippet` object types added to the global search
- `SnippetText` renders highlighted HTML safely through `dangerouslySetInnerHTML`

### SSH askpass — regression fix
- `ssh_exec.py`: when `sshpass` / askpass-helper was used the password was read from the wrong slot of the new credential object, causing auth failures after the credential schema migration

---

## v0.2.0 — 2026-05-13

### SSH Pivot — исправление зависания агента при скане через SOCKS-прокси

**Проблема:** при запуске сканирования через pivot-хост с SOCKS4/5-прокси gunicorn-воркер зависал намертво — процесс SSH оставался живым после таймаута и держал pipe открытым, блокируя `communicate()`.

**Причина:** `setsid -w` оборачивал SSH-процесс, делая его внуком (не прямым ребёнком). `proc.kill()` убивал setsid, но SSH оставался сиротой с открытыми pipe'ами.

**Исправления (`backend/app/core/ssh_exec.py`):**
- Убран `setsid -w` — SSH теперь прямой дочерний процесс
- Добавлен `start_new_session=True` во все три точки запуска (`run_ssh_command`, `run_ssh_command_cancellable`, `run_ssh_command_streaming`) — даёт тот же изоляционный эффект, но с правильной иерархией процессов
- `proc.kill()` теперь гарантированно закрывает pipe'ы и разблокирует `communicate()`

**Таймаут proxychains (`backend/app/core/exec_context.py`):**
- В конфиг proxychains добавлены `tcp_connect_time_out 5000` и `tcp_read_time_out 15000`
- При недоступном SOCKS-прокси команда теперь завершается за ~5 с вместо вечного ожидания

---

### Scope — точка входа в инфраструктуру (`is_entry`)

**Новое поле `is_entry` на Scope** (Boolean, default false):
- Отмечает scope, через который проходит входящий трафик атакующего (VPN-шлюз, DMZ и т.п.)
- Только один scope на проект может иметь `is_entry=true` — при установке флага у другого scope старый сбрасывается автоматически (как в `create`, так и в `update`)
- В UI отображается бейдж `· entry` в списке scope'ов; чекбокс в форме создания/редактирования

**Backend:**
- `ALTER TABLE scopes ADD COLUMN is_entry BOOLEAN NOT NULL DEFAULT FALSE` — добавлено в `main.py`
- `models.py`, `schemas.py` — поле добавлено в `Scope`, `ScopeCreate`, `ScopeUpdate`
- `routers/scopes.py` — авто-сброс предыдущего `is_entry` при POST и PATCH

---

### Topology Smart Build — исправления и улучшения

#### Исправление crash в транзитном блоке
- `float(region.get("x", 0))` заменено на `float(region.get("x") or 0)` во всех вспомогательных функциях (`_region_center`, `_place_between_regions`, `_place_on_region_edge`) — `dict.get(key, default)` возвращает `None` (не default) при `key: null` в JSON
- Транзитный блок обёрнут в `try/except Exception` — ошибки позиционирования не ломают build целиком

#### Статусы нод больше не сбрасываются после Smart Build (двойная защита)

**Backend (`topology.py`):**
- Добавлена иерархия приоритетов `_STATUS_RANK` (unknown < alive < up < scanned < access < owned/pwned < attacker)
- При синхронизации `Host.status → node.status` статус ноды обновляется только если хост-статус ≥ текущего статуса ноды — исключает откат "scanned" → "unknown"

**Frontend (`applySyncEvent.js`):**
- При получении `layout_applied` / `topology_rebuilt` фронтенд сравнивает текущий статус ноды с входящим и берёт лучший — по `node.id` и `node.host_id`
- `layout_reset` по-прежнему полностью заменяет состояние (намеренный полный сброс)

#### Направление трафика соответствует логике атаки

**Раньше:** uplink-ребро вело `Attacker → transit-хост` (VPN-GW), минуя entry-gateway.

**Теперь:** uplink ведёт к **entry scope gateway** (`gateway_ip` scope с `is_entry=true`). Полная цепочка видна на карте:
```
Attacker → GW_EXTERNAL (entry)  →  VPN-GW (pivot)  →  Internal hosts
```
Если entry-gateway не настроен — fallback на transit-хост (прежнее поведение).

---

### SSH Proxy — многоуровневая поддержка прокси для attacker-цели

**Новая система маршрутизации SSH-команд** (`backend/app/core/`):

- `exec_context.py` — экспортирует переменные окружения `ROOTNOTES_EXEC_*` (jump-host, proxy) перед выполнением команды; оборачивает команду в proxychains при SOCKS4/5
- `route_selection.py` — алгоритм выбора маршрута: direct → jump → proxy; учитывает доступность из attacker-цели
- `socks_proxy.py` — Python SOCKS5-клиент для `ProxyCommand` в OpenSSH (без внешних зависимостей)

**Поддерживаемые прокси для attacker SSH-target:**
| Тип | Описание |
|-----|----------|
| `jump` | SSH Jump Host (ProxyJump / ProxyCommand) |
| `socks5` | SOCKS5 через `socks_proxy.py` ProxyCommand |
| `socks4` | SOCKS4 через proxychains |

**SystemModulesView:** в UI attacker-targets добавлены поля proxy-конфигурации с валидацией.

---

### C2 — уточнение семантики статусов хостов

- При синхронизации C2-агентов (CS/Sliver/MSF/Adaptix) статус хоста выставляется строго по иерархии: если хост уже `owned/pwned`, агент C2 не понижает статус до `access`
- Корректная обработка `last_seen` и `is_active` для разных коннекторов
- Исправлен тайпо endpoint в Cobalt Strike коннекторе: `/api/v1/beacon` → `/api/v1/beacons`

---

## 2026-05-09 — Smart topology build + Full-text job output search + Attacker SSH improvements

### Smart topology build (`POST /topology/smart-build`)

Новый endpoint вместо flat subnet-mesh строит многослойный граф:

**Источники данных (в порядке приоритета):**
1. `CredHostNote.access[]` — подтверждённые access-рёбра (ssh/winrm/smb_admin/local_admin) с `verified=true, confidence=1.0, source=cred_validation`
2. Jobs `bulk_exec done` с `access_role` в result_json — `source=bulk_exec, verified=true`
3. `HostActivity` с типом `exec/postex/lateral` — `source=host_activity, confidence=0.9`
4. `host.domain` + DC-детектирование (порты 88+389, тег dc, роль domain_controller) → `domain_member` рёбра `source=auto, confidence=0.8`
5. Subnet hub-and-spoke inference — `same_subnet/lan, source=auto, confidence=0.7-0.9`

**Регионы:** из Scope CIDR-записей — автоматический bounding box по нодам в подсети

**Для каждого ребра:** `type, label, source, reason, state (observed/inferred), verified, confidence, is_manual`

**Стили рёбер:**
- Access (ssh/winrm/local_admin): зелёный solid/dashed (верифицировано / нет)
- Lateral/pivot: жёлтый анимированный
- domain_member: фиолетовый пунктир
- same_subnet/lan: тёмно-серый пунктир

**Ноды:** обогащены `domain`, `tags`, `role` из host metadata; роль инфицируется из порт-сигнатур (domain_controller, web_server, database, jump_host, router)

**Правила:** manual/observed рёбра сохраняются всегда; auto-рёбра перестраиваются при каждом вызове

Кнопка **Smart Build** (зелёная) в тулбаре Network Map рядом с Auto-layout.

---

## 2026-05-09 — Full-text job output search + Attacker SSH improvements + Cred Matrix

### Full-text search по job output
- Новый query-param `output_search` в `GET /api/projects/{pid}/jobs` — SQL `ilike` по полям `output` и `error_output`
- В JobsView добавлено поле **"Search in output…"** с дебаунсом 400ms и кнопкой очистки
- При активном output_search: строки с совпадением авто-разворачиваются, бейдж показывает количество найденных job'ов
- В развёрнутом output: совпадающие строки выделяются желтым (`<mark>`), несовпадающие затемнены (opacity 0.3), счётчик совпадающих строк сверху

---

## 2026-05-09 — Attacker SSH improvements + Cred Matrix

### Credential × Host Access Matrix
- Новый endpoint `GET /api/projects/{pid}/cred-matrix` — возвращает `{creds, hosts, matrix}` по данным `CredHostNote`
- `CredMatrix.jsx` — heatmap-компонент: sticky-заголовки, вертикальный текст для хостов, tooltip с access-ролями и заметками
- Фильтры: Все / Успешные / Проверенные; поиск по username/domain/service; stat-бейджи
- Переключатель **⊞ Matrix** в хедере вкладки Credentials

### Transport Fallback для Attacker SSH
- `ssh_exec.py`: добавлен `is_transport_failure(result)` — детектирует недоступность хоста (exit_code 255 + stderr-паттерны)
- `bulk_actions.py`: `_resolve_exec_ssh_configs()` возвращает список кандидатов; `bulk_exec` и `validate_cred` перебирают их при transport-ошибке
- `attacker_exec.py`: `_exec_ssh_candidates` + fallback-цикл; HTTP 502 если все таргеты недоступны
- Auth-ошибки и ошибки команд не вызывают fallback — только network-недоступность

### Attack Path Graph — исправление направлений стрелок
- Row-wrap рёбра теперь маршрутизируются через низ/верх нод (не через правый край)
- Два отдельных маркера: `#arrow-h` (→, для рёбер в строке) и `#arrow-v` (↓, для межстрочных переходов)
- Квадратичные безье (`Q`) для скруглённых углов пути

---

## 2026-05-08 — Fixes

### Notifications
- Исправлена DNS-проблема в backend-контейнере: добавлены `dns: [8.8.8.8, 1.1.1.1]` в docker-compose.yml
- Добавлены события `job_done` и `job_failed` в UI настроек уведомлений
- Новый endpoint `GET /api/notifications/telegram/chat-id` — auto-detect chat_id через Telegram `getUpdates`
- Кнопка **Detect** в UI Telegram-секции с выпадающим списком найденных чатов

### C2 — Cobalt Strike
- Исправлен тайпо `/api/v1/beacon` → `/api/v1/beacons` в `_cs_live_agents`

### Sliver Builder
- Конфиг builder перенесён из `/tmp/rootnotes.cfg` в `/etc/sliver-builder.cfg` (персистентный)
- `sliver-builder.service` обновлён — больше не падает в crash-loop после перезагрузки
- Implant generation: Windows x64 EXE через `generate --mtls 172.16.100.188 --os windows --arch amd64`

---

## 2026-05-07 — Session Summary

### UI / Frontend

#### Sidebar (AppChrome)
- Collapsed sidebar: иконки теперь с отступами `12px 14px`, gap 10 — те же пропорции что в развёрнутом режиме
- Все иконки уникальны (новые: `jobs`, `graph`, `book` для Domains, KB, Jobs)
- Удалена вкладка **Attack Graph** (перекрывала Network Map, граф не строился)

#### Overview (Dashboard)
- Новый экран `/overview` — вкладка первая в сайдбаре
- 5 stat-карточек: Hosts / Findings / Creds / Objectives / Notes (кликабельные, переход на нужную вкладку)
- Findings by severity — горизонтальные бары
- Hosts by status — dots с количеством
- Последние 8 событий Timeline с `timeAgo`
- Прогресс чеклиста по фазам

#### Report (HTML Export)
- Секция Findings с полными деталями (severity badge, CVE, description, recommendation)
- Кнопка **Export HTML** — генерирует standalone HTML-файл на клиенте (без запросов к серверу)

#### Import — Scanner Files
- В ImportModal добавлена вкладка **Scanners** с загрузкой Nessus (`.nessus`) и Burp Suite (`.xml`) файлов
- Использует `api.importNessus(pid, file)` и `api.importBurp(pid, file)`

#### Attack Path
- Переключатель List | Graph в хедере вкладки
- SVG-граф шагов с нодами 160×80px, цветами по типу (`initial_access`, `lateral`, `escalation`, `objective`), стрелками, нумерацией шагов

#### Toast Notifications
- Глобальная система toast (`Toast.jsx`): `toast()`, `toastError()`, `toastSuccess()`, `toastWarn()`
- Анимация `fadeInUp`, фиксированный bottom-center
- Заменяет все `alert()` / `confirm()` вызовы

#### Common Styles
- `frontend/src/styles/common.js` — цвета `C` и объекты стилей `S` (input, select, textarea, card, badge)
- `frontend/src/hooks/useEntityList.js` — generic хук для списков с loading/error состоянием

#### Notifications Settings (Admin)
- Добавлены события **Job completed** и **Job failed** в список событий
- Кнопка **Detect** для автоопределения Telegram chat_id через `getUpdates` API
- Выпадающий список найденных чатов — клик сразу вставляет ID

---

### Backend

#### DB Indexes (`main.py`)
Добавлено 17 индексов для ускорения запросов:
```
idx_hosts_pid, idx_hosts_ip, idx_creds_pid, idx_notes_pid, idx_notes_ts,
idx_findings_pid, idx_loots_pid, idx_host_activities_pid, idx_host_activities_host_id,
idx_cred_host_notes_cred_id, idx_cred_host_notes_host_id, idx_attack_steps_path_id,
idx_timeline_events_pid, idx_timeline_events_ts, idx_checklist_items_pid,
idx_scopes_pid, idx_objectives_pid
```

#### Search (`routers/search.py`)
- Переписан на SQL `ilike` с `OR`-условиями вместо загрузки всех записей в память
- `query.limit(limit).all()` вместо `.all()` → `[:limit]`

#### Job Notifications (`core/job_tracker.py`)
- `finish_job()` теперь отправляет уведомление при `status in ("done", "failed")`
- Событие: `job_done` / `job_failed`, заголовок: `"Job done: <title>"`, тело: target или project ID + error excerpt

#### C2 Integrations (`routers/c2.py`)
| Коннектор | URL | Аутентификация |
|-----------|-----|----------------|
| **Cobalt Strike** | `http(s)://<host>/api/v1/beacons` | Bearer token |
| **Sliver** | `http://<host>/v1/sessions` + `/v1/beacons` | Bearer token |
| **Metasploit (MSFRPC)** | `http://<host>:55553/api/1.0/` | login → temp token |
| **Adaptix** | WS/REST API | token + password |

- Исправлен тайпо: `/api/v1/beacon` → `/api/v1/beacons` в `_cs_live_agents`
- Metasploit: `_msf_sync` подключается через MSFRPC HTTP API (msfrpcd)

#### Notifications (`routers/notifications.py`, `core/notifications.py`)
- `GET /api/notifications/telegram/chat-id` — вызывает `getUpdates` бота и возвращает список чатов с названиями
- Поддерживаемые каналы: Telegram, Slack webhook, Custom webhook (POST JSON)
- Конфиг в `GlobalSetting` key `"notifications"`, загружается при каждом вызове (без перезапуска)

#### Docker (docker-compose.yml)
- Backend-контейнер получил DNS-серверы `8.8.8.8` / `1.1.1.1` для доступа к внешним API (Telegram и др.)

---

### Инфраструктура (172.16.100.188)

#### Sliver C2 v1.7.3
| Компонент | Описание |
|-----------|----------|
| `sliver.service` | Teamserver, gRPC multiplayer port 31337 |
| `sliver-proxy.service` | FastAPI REST-прокси (`/opt/sliver-proxy/`) |
| `sliver-builder.service` | External builder для генерации implant'ов |

**Sliver REST Proxy** (`/tmp/sliver_proxy.py`):
- Endpoint: `http://172.16.100.188:8888/` (или настроенный порт)
- Bearer token: `rtnotes-sliver-proxy-token`
- `GET /health`, `GET /v1/sessions`, `GET /v1/beacons`

**Статус интеграции**: ✅ подключение работает, сессии возвращаются (пусто — нет активных агентов)

#### Cobalt Strike 4.9.1 (Docker)
| Компонент | Значение |
|-----------|----------|
| Image | `3ayazaya/cobalt-strike:4.9` |
| Container | `cs-stf-otbor` |
| Teamserver port | `50050/tcp` |
| Password | `TestPass1234!` *(тестовая)* |
| Compose path | `/home/user/cobalt-strike/docker-compose.yml` |

**REST Mock API** (`/home/user/cs_mock_api.py`):
- Port `8080`, token `rnotes-test-token`
- Эмулирует `/api/v1/beacons` и `/api/v1/credentials`
- Используется для тестирования RootNotes CS-интеграции

**Причина мока**: CS teamserver использует бинарный Aggressor-протокол (не HTTP REST). Для продакшн-интеграции нужен один из вариантов:
1. CS REST API Plugin (official, платный)
2. Aggressor Script с HTTP сервером
3. Python-клиент, реализующий Sleep/Aggressor binary protocol

**Статус интеграции**: ✅ test + sync работают через мок (`hosts_created: 2, creds_created: 4`)

#### Metasploit (Attacker Host / Kali)
- MSFRPC запускается: `msfrpcd -P <password> -S -f -a 0.0.0.0 -p 55553`
- RootNotes коннектор: `type: "metasploit"`, url `http://<kali>:55553`

---

### Известные проблемы / TODO

| # | Проблема | Статус |
|---|----------|--------|
| 1 | Sliver implant generation возвращает NOT_FOUND | Возможна несовместимость sliver-py 0.0.19 с Sliver v1.7.3 API |
| 2 | CS бинарный протокол не реализован | Нужен CS client JAR или REST API плагин |
| 3 | `deepcopy` not defined в topology auto-build | Нужен `from copy import deepcopy` в соответствующем файле |
