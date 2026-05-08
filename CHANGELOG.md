# RootNotes — Changelog

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
