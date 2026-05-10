# RootNotes

Self-hosted red team workspace for tracking engagements end-to-end — hosts, credentials, findings, notes, loot, attack paths, and reporting in one interface.

![Network Map](docs/screenshots/03_network.png)

---

## Features

| Module | What it does |
|--------|-------------|
| **Hosts** | Inventory with status (pwned / access / up), roles, ports, services, tags, linked creds |
| **Credentials** | Plaintext, NTLM, Kerberos tickets; domain/local, cracked state, host linking |
| **Findings** | Severity, CVE/CVSS, proof, recommendations, workflow status; report-ready |
| **Notes** | Markdown with attachments, phases, tags, live collaboration via WebSocket |
| **Loot** | Files, hashes, secrets, configs — upload/download with auth, host-linked |
| **Attack Path** | Ordered escalation steps with MITRE technique fields |
| **Network Map** | Interactive canvas with VLAN regions, node roles, overlay modes (threats / sessions / access / roles) |
| **Objectives** | Mission goals with capture status and operator attribution |
| **Playbooks** | Automated job sequences with live step state polling |
| **Knowledge Base** | Markdown articles (global or project-scoped) with full-text search |
| **Search** | Full-text across all entities with filter tokens (`type:host`, `severity:critical`, `service:smb`) |
| **Report** | Executive summary with stats, compromised hosts, cracked creds, timeline |
| **Timeline** | Per-project audit log of all operator activity |

---

## Screenshots

### Projects
![Projects](docs/screenshots/02_projects.png)

### Network Map — overlay modes: Threats · Sessions · Access · Roles
![Network](docs/screenshots/03_network.png)

### Hosts
![Hosts](docs/screenshots/04_hosts.png)

### Credentials
![Credentials](docs/screenshots/05_creds.png)

### Findings
![Findings](docs/screenshots/06_findings.png)

### Notes (Markdown)
![Notes](docs/screenshots/07_notes.png)

### Loot
![Loot](docs/screenshots/08_loot.png)

### Knowledge Base
![Knowledge Base](docs/screenshots/09_kb.png)

### Global Search
![Search](docs/screenshots/10_search.png)

### Report
![Report](docs/screenshots/15_report.png)

---

## Quick Start

**Requirements:** Docker, Docker Compose

```bash
# 1. Configure
cp .env.example .env   # set JWT_SECRET, DB_PASSWORD, ADMIN_PASSWORD

# 2. Build and start
docker compose up -d --build

# 3. Open
open http://localhost:3000
```

Default credentials (if `ADMIN_PASSWORD` is not set, backend prints the generated password to logs on first start):

```
admin / admin
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Host port exposed by nginx |
| `JWT_SECRET` | `change-me-in-production` | JWT signing key — **change before exposing** |
| `DB_USER` | `rtnotes` | PostgreSQL user |
| `DB_PASSWORD` | `rtnotes_secret` | PostgreSQL password |
| `DB_NAME` | `rtnotes` | PostgreSQL database name |
| `ADMIN_USERNAME` | `admin` | Initial admin username |
| `ADMIN_PASSWORD` | *(auto-generated)* | Initial admin password |

---

## Architecture

```
nginx ──► frontend  (React + Vite, static build)
     ──► backend   (FastAPI + SQLAlchemy + asyncio worker pool)
                └──► PostgreSQL 16
```

- **Auth:** JWT bearer tokens, role-based (`admin` / `member`)
- **Realtime:** WebSocket per-project — presence and live entity sync
- **Workers:** bounded async job pool with startup recovery (interrupted jobs → failed, queued → re-submit)
- **Storage:** uploaded files in `data/uploads/`, database in `data/postgres/`

---

## Security Notes

- Change `JWT_SECRET` and `DB_PASSWORD` before any non-local deployment
- Designed for internal trusted networks — no public internet exposure assumed
- All file downloads require a valid auth token (passed as `?token=` or `Authorization` header)
