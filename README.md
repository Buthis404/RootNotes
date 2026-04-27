# RootNotes

A self-hosted, collaborative note-taking platform built for red team operators and penetration testers. Organize engagements, track hosts, credentials, findings, loot, and attack paths — all in one dark-themed workspace.

---

## Screenshots

### Projects
![Projects](docs/screenshots/02_projects.png)
*Multiple active engagements with host, credential, and finding counters*

### Notes (Markdown editor)
![Notes](docs/screenshots/03_notes.png)
*Markdown notes with syntax highlighting, tags, and real-time sync*

### Host Tracker
![Hosts](docs/screenshots/04_hosts.png)
*Hosts with status badges, service tags, open ports, and credential links*

### Credential Manager
![Credentials](docs/screenshots/05_creds.png)
*NTLM hashes, plaintext passwords, domain creds — secrets blurred by default*

### Findings
![Findings](docs/screenshots/06_findings.png)
*Severity-ranked vulnerability tracker with CVE, CVSS, and remediation*

### Loot
![Loot](docs/screenshots/07_loot.png)
*Post-exploitation loot: hashes, configs, files, secrets*

### Objectives
![Objectives](docs/screenshots/08_objectives.png)
*Flag capture tracker with point scoring and timestamps*

### Timeline
![Timeline](docs/screenshots/13_timeline.png)
*Automatic audit log of all actions across the engagement*

### Scope
![Scope](docs/screenshots/14_scope.png)
*In-scope/out-of-scope CIDR ranges, domains, with live IP checker*

### Global Search (Ctrl+K)
![Search](docs/screenshots/10_search.png)
*Cross-project search across hosts, creds, notes, findings, and loot*

### Admin Panel
![Admin](docs/screenshots/11_admin.png)
*Multi-user management with role control and online presence indicators*

---

## Features

| Module | Description |
|--------|-------------|
| **Projects** | Manage multiple engagements with target IP, OS, status, and stats |
| **Notes** | Markdown editor with file attachments and real-time co-editing |
| **Hosts** | Track IPs, ports, services, tags, status; multi-host credential linking |
| **Credentials** | Store hashes, plaintext, keys, tokens; domain cred propagation |
| **Findings** | Severity tracker with CVSS/CVE, template library, Nessus XML import |
| **Loot** | Catalog files, hashes, configs, secrets extracted post-exploitation |
| **Scope** | CIDR/domain in-scope management with live IP membership check |
| **Objectives** | BAS objectives and CTF flag capture with scoring |
| **Attack Path** | Visual kill chain diagram builder with MITRE technique tagging |
| **Checklist** | Phase-based methodology checklist (recon → scan → exploit → report) |
| **Network** | Interactive topology canvas with drag-and-drop nodes |
| **Timeline** | Automatic event log of every action across an engagement |
| **Cheatsheet** | 400+ searchable red team commands with copy-to-clipboard |
| **Report** | Auto-generated Markdown engagement report |
| **Global Search** | Ctrl+K search across all entities in all projects |
| **User Management** | Multi-user with admin/user roles and real-time presence indicators |
| **Import/Export** | Full project ZIP export/import; Nmap XML and Nessus XML import |

---

## Quick Start

### Requirements
- Docker and Docker Compose

### 1. Clone

```bash
git clone https://github.com/youruser/rootnotes.git
cd rootnotes
```

### 2. Configure

```bash
cp .env.example .env
```

Edit `.env`:

```env
# Database
DB_PASSWORD=strong_random_password

# JWT signing secret — generate with: openssl rand -hex 32
JWT_SECRET=your-long-random-secret-here

# Admin account (auto-created on first run if no users exist)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=strong_admin_password

# Exposed port
PORT=3000
```

> If `ADMIN_PASSWORD` is left empty, a random password is generated and printed to the backend logs on first run.

### 3. Start

```bash
docker compose up -d --build
```

### 4. Open

Navigate to [http://localhost:3000](http://localhost:3000) and log in with your configured admin credentials.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ADMIN_USERNAME` | `admin` | Initial admin username |
| `ADMIN_PASSWORD` | *(random)* | Initial admin password. If unset, auto-generated and logged on first run |
| `DB_USER` | `rtnotes` | PostgreSQL user |
| `DB_PASSWORD` | `rtnotes_secret` | PostgreSQL password — **change this** |
| `DB_NAME` | `rtnotes` | PostgreSQL database name |
| `JWT_SECRET` | `change-me-in-production` | JWT signing secret — **must be changed** |
| `PORT` | `3000` | Host port exposed via nginx |

---

## Usage Examples

### Adding a project

1. Go to **Projects** → **New Project**
2. Enter the name, target IP/CIDR, OS type, and description
3. Click **Create**, then click the card to select the project

### Importing an Nmap scan

```bash
nmap -sV -sC -p- 10.10.100.0/24 -oX scan.xml
```

1. **Hosts** tab → **Nmap** button
2. Paste the XML output
3. Review discovered hosts → **Import**

### Importing Nessus results

1. **Findings** tab → **Nessus** button
2. Upload your `.nessus` export file
3. Review deduplicated findings → **Import**

### Bulk credential import

1. **Creds** tab → **Bulk** button
2. Paste in `username;secret;type;service;host;cracked` format:

```
Administrator;aad3b435:8846f7eaee8fb117ad06bdd830b7586c;ntlm;SMB;10.10.10.5;false
svc_backup;Backup2024!;plain;SMB;10.10.10.20;true
tomcat;tomcat;plain;HTTP;10.10.10.10;true
DOMAIN\jsmith;Summer2024!;plain;RDP;10.10.10.50;true
```

### Export a project

In the **Projects** tab, click the **ZIP** button on any project card. The archive includes notes, hosts, credentials, findings, loot, checklists, objectives, attack paths, and file attachments.

### Import a project

In the **Projects** tab, click **Import ZIP** and select a previously exported `.zip` file.

---

## Collaboration

RootNotes supports real-time multi-operator collaboration:

- **WebSocket sync** — changes to any entity propagate instantly to all connected users
- **Presence indicators** — see who is online in the sidebar; orange dot indicates active note editing
- **Shared timeline** — every action is logged with the acting user's name

### Creating team accounts

As admin: **Admin panel** (shield icon, bottom of sidebar) → **Add user**

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, Vite |
| Backend | FastAPI (Python 3.11) |
| Database | PostgreSQL 16 |
| Auth | JWT (HS256) + bcrypt |
| Real-time | WebSockets |
| Proxy | Nginx |
| Runtime | Docker Compose |

---

## Security

- Change `JWT_SECRET` and `DB_PASSWORD` before any real deployment
- Designed for **internal/VPN-only** access — do not expose directly to the internet
- File uploads are stored locally with sanitized filenames
- Credential secrets are blurred in the UI by default

---

## License

MIT
