# RootNotes — Changelog

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
