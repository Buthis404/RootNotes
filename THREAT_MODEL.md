# Threat Model

This is a STRIDE-flavoured threat model for RootNotes. It enumerates
the actors we consider, what each one can attempt, and which controls
in the platform address each attempt. Companion document:
[SECURITY.md](SECURITY.md).

The model is intentionally narrow: RootNotes is deployment-trusted
software for red-team / pentest operators. It is **not** a public
SaaS, and the model reflects that.

---

## 1. Assets (what we care about)

In rough order of blast radius:

1. **Credential secrets** — direct authentication material to client
   systems. Compromise here equals direct compromise of the engagement
   target.
2. **C2 operator material** — tokens / operator configs for live
   attacker infrastructure (Adaptix, Mythic, Sliver). Compromise gives
   the attacker control of *our* C2.
3. **Loot files** — NTDS dumps, captured hashes, configuration files,
   screenshots. Often contain the most damaging raw material.
4. **Confidential notes** — free-form text the team marked as
   `confidential` / `secret` / `sensitive` / `opsec` / `restricted`.
5. **Project graph + audit log** — aggregated picture of who-did-what.
   Useful for an attacker reconstructing the engagement; also the
   primary forensic record.
6. **Non-confidential operational data** — host inventory, findings,
   scope, attack path. Lower direct blast radius but still
   client-confidential.

Each asset has a row in the matrix at §4.

---

## 2. Trust boundaries

```text
┌─────────────────────────────────────────────────────────────────┐
│  Public internet  (UNTRUSTED — assumed never reaches us)        │
└────────────────────────┬────────────────────────────────────────┘
                         │  TLS / VPN / reverse proxy
┌────────────────────────▼────────────────────────────────────────┐
│  Operator network  (TRUSTED — bounded by reverse proxy)         │
│  ┌────────────┐   ┌────────────┐   ┌──────────────────┐         │
│  │   nginx    │──▶│  frontend  │──▶│  backend (API)   │         │
│  │            │   │  (static)  │   │  + worker pool   │         │
│  └────────────┘   └────────────┘   └──┬──────┬────────┘         │
│                                       │      │                  │
│                          ┌────────────▼─┐    │                  │
│                          │  Redis       │    │ (WS pub/sub)     │
│                          │  (pub/sub +  │    │                  │
│                          │   presence)  │    │                  │
│                          └────────────┬─┘    │                  │
│                                       │      │                  │
│  ┌────────────────────────────────────▼──────▼──────────────┐   │
│  │  Trusted-data zone                                        │   │
│  │   • PostgreSQL  (creds, notes, loot.value: ciphertext)    │   │
│  │   • /data/uploads/  (loot files: Fernet-encrypted new)    │   │
│  │   • /data/uploads/audit/timeline.jsonl  (append-only)     │   │
│  │   • /data/secret.key  (Fernet key, 0600)                  │   │
│  │   • /data/.jwt_secret  (HS256 signing key)                │   │
│  └───────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                         │
                         │  outbound only
┌────────────────────────▼────────────────────────────────────────┐
│  External services we touch (NOT trusted with our data)         │
│   • Attacker SSH host  ──▶  pentest target network              │
│   • C2 teamservers (Adaptix / Mythic / Sliver multiplayer)      │
│   • S3/Minio  (optional WORM audit log forward)                 │
└─────────────────────────────────────────────────────────────────┘
```

**Boundaries we enforce:**

- nginx → backend: HTTP only. Backend assumes the reverse proxy did
  TLS and rate limiting.
- API → DB: SQLAlchemy ORM with prepared parameters. No string-built
  SQL.
- API → filesystem: paths to `/data/uploads/` are computed
  server-side; user-supplied identifiers are not interpolated into
  paths without a UUID prefix.
- API → C2 teamserver: outbound TLS, mTLS in the Sliver case;
  credentials decrypted at use, not held in memory longer than the
  call.
- API → Redis: localhost or internal Docker network only; Redis holds
  serialized WebSocket event payloads (same data as WS broadcasts).
  Redis is not auth-gated by default — it must be on an isolated
  network segment. A compromised Redis instance can replay WS events
  to all connected clients, but cannot forge DB-backed data.

---

## 3. Actors

Five categories. Naming follows the STRIDE convention loosely.

### A1. External attacker (no credentials)

Someone who reaches the network port but has no valid user account.

| Capability | Mitigation |
|---|---|
| Hit any unauthenticated endpoint | All endpoints except `/health` and `/auth/login` require a valid JWT |
| Brute-force `/auth/login` | SlowAPI rate-limiter (5/min per IP); deployment expectation = put a reverse proxy in front |
| Try to access `/data/uploads/...` directly | Not exposed; files served only through `/api/loot/{id}/download` which checks auth + project membership |
| Connect to the WebSocket without a token | `decode_ws_token()` returns `None` → close code 4001 |

### A2. Authenticated user, no project membership

A real RootNotes user who has not been added to the project they're
poking at.

| Capability | Mitigation |
|---|---|
| GET / POST anything in project P | `check_pid_access()` returns 404 (`not_member` — we deliberately don't reveal that the project exists) |
| Subscribe to `/ws/{pid}` for project P | WebSocket endpoint refuses with close code 4003 if the user is not a member |
| Search globally | `/api/search` uses `get_user_member_pids()` — only returns hits from projects the user is a member of |
| Read global KB articles | **Allowed by design** (curated content). Write/delete on global KB is admin-only |

### A3. Authenticated project member with low privilege (`viewer`, `auditor`)

Has been invited, but with read-only or audit-only role.

| Capability | Mitigation |
|---|---|
| Read credential plaintexts via REST | `credentials.read_secret` not in role → secret field is replaced with `""` in `_cred_out()` |
| Read credential plaintexts via WS | WS broadcast policy: lacks `credentials.read_secret` → `secret` redacted to `""` in the per-recipient payload |
| Read credential existence at all (auditor) | Auditor lacks `credentials.read` → list/get endpoints 403; WS broadcast skips |
| Mutate hosts/findings/notes | Missing `*.create` / `*.update` / `*.delete` → 403 |
| Apply topology changes | `topology.apply` not in role → 403 |
| Read confidential notes | Note content is encrypted server-side. Decrypt is gated by `notes.read` AND a per-note check on confidential tags |
| Download sensitive loot | Server-side `/api/loot/{id}/download` checks `loot.read`; for sensitive types, also writes an audit event |

### A4. Authenticated project member with high privilege (`editor`, `operator`, `admin`, `owner`)

Has been invited with operational rights.

| Capability | Mitigation |
|---|---|
| Read credential plaintexts (intended) | Permitted. Every list / host-actions / bulk-exec / c2-exec / export with secrets writes an `audit/...` event with the cred id, count, and context |
| Mass-export the project as a ZIP | `project.export` required; export with secrets is audited; the ZIP is auto-encrypted with a per-export password when secrets are included |
| Run arbitrary commands on attacker SSH | Job runs under the attacker host's SSH credentials (separate from RootNotes auth). All output is captured to `command_outputs` and broadcast under the same RBAC policy |
| Pivot through registered C2 sessions | `c2.exec` step type requires the relevant project permissions; agent_id is looked up from the cfg's live agents endpoint, not user-supplied as a raw target |
| Self-register a C2 teamserver bound to their project | Only `owner` of the listed `project_ids`; cannot make the integration global; cannot widen scope to projects they don't own |

### A5. Global admin (`User.role="admin"`)

Has `require_admin` access. Effectively a superuser at the platform
level. Mitigations focus on observability rather than prevention.

| Capability | Mitigation |
|---|---|
| Read every project | Project membership not enforced for admin; this is intended |
| Manage users, system modules, global C2 | `require_admin` enforced; audit trail records logins and module toggles |
| Pull the Fernet key off the filesystem | Use `ENCRYPTION_KEY` env from a secret manager so it never lands on disk |
| Read the audit log for their own access | Yes — by design. Out-of-band log forwarding (syslog → SIEM) is the operator's responsibility |

### A6. Host operator (server admin, root on the box)

Can read files on the machine. Out of RootNotes' control.

| Capability | Mitigation |
|---|---|
| Read `data/postgres/*` and `data/secret.key` | None within RootNotes. Encrypt the data volume at the OS level (LUKS, cloud-managed disk encryption). Inject `ENCRYPTION_KEY` from a secret manager so it never lands on `/data/secret.key` |
| Read `data/uploads/*.zip` | None within RootNotes. Loot files are plaintext on FS |
| Dump process memory containing decrypted secrets | None. In-process plaintext during command-rendering is short-lived but not protected |

---

## 4. Asset / Actor matrix

Cell = the strongest action the actor can attempt against the asset
under the current controls.

| Asset \ Actor | A1 external | A2 no membership | A3 viewer/auditor | A4 editor/operator/owner | A5 global admin | A6 host-root |
|---|---|---|---|---|---|---|
| Credential secrets | blocked (auth) | blocked (404) | redacted (`""`) on REST + WS | **read** (audited) | **read** | **read** (filesystem) |
| C2 operator material | blocked | blocked (404) | invisible (admin-only or owner-scoped) | manage if owner of bound projects | **manage** | **read** (filesystem) |
| Loot files | blocked | blocked | metadata only (sensitive ones audited) | **download** (audited) | **download** | **read** (filesystem) |
| Confidential notes | blocked | blocked | metadata only; content decrypted only if `notes.read` AND not on the redact list | **read** | **read** | **read** (filesystem) |
| Hosts / findings / network | blocked | blocked | **read** | **read + mutate** | **read + mutate** | **read** (filesystem) |
| Audit log | blocked | blocked | per-project audit events visible if role allows timeline read | **read** | **read everywhere** | **read** + DB tamper (detectable via HMAC + JSONL mirror) |

---

## 5. Specific attack scenarios

### S1. "I'm an auditor, can I see hashed-but-not-cracked NTLM creds?"

No.

- `auditor` role lacks `credentials.read` entirely.
- REST list/get returns 403.
- WebSocket broadcasts of `cred:create`/`cred:update` skip the
  auditor entirely (policy: required perm = `credentials.read`).
- The auditor sees host and finding context but no cred existence.

### S2. "I'm a viewer in a long-running engagement. Can I scrape plaintext over time via the WS event stream?"

No.

- WS broadcast carries data shaped from `_cred_out()`, but that is
  re-evaluated per recipient. The per-WS filter in `_local_broadcast`
  checks the recipient's permission set and zeroes `cred.secret`
  for anyone without `credentials.read_secret`.
- Listening passively to the stream as a viewer only yields cred
  existence + metadata, never the secret.

### S3. "Project owner of project A wants to read project B."

Cannot via UI / API.

- `check_pid_access(db, pid=B, user)` looks up `ProjectMember` rows
  where `user_id=user.id AND project_id=B AND is_active=True`. If
  none, 404.
- Search is scoped to the owner's member projects.
- The audit log for project B is not visible.

### S4. "Global admin reads a project they aren't a member of."

Allowed by design — admin-bypass in `_evaluate()`.

- Every admin access produces audit / event-log entries in that
  project's timeline.
- Out-of-band SIEM forwarding is recommended.
- Use of `member` role + explicit project membership is the
  recommended pattern for everyday operations; reserve `admin` for
  platform maintenance.

### S5. "Attacker on the same LAN that has snapshot access to /data."

Recoverable plaintext IF `ENCRYPTION_KEY` is at the default
filesystem location.

- They get PostgreSQL data dir + `/data/secret.key` → Fernet keys
  unlock cred / note / loot ciphertext.
- They get `/data/uploads/` → loot files in plaintext.
- They get `/data/.jwt_secret` → can forge user sessions.

Mitigation: deploy `ENCRYPTION_KEY` and `JWT_SECRET` via env from a
secret manager, mount `/data` on encrypted storage.

### S6. "Insider with editor role exfiltrates the entire credential vault."

Possible by design (editor has `credentials.read_secret`). Detection:

- `read_credential_secrets` audit event on every list call
- `export_with_secrets` audit event on full project export
- `secret_used_bulk_exec` audit event when a cred is used to fan
  out to many hosts at once (anomalous host_count is a signal)
- `secret_used_c2_exec` audit event per c2 exec invocation

Prevention is out of scope; observability is in scope.

### S7. "Compromised browser session token (XSS via a phishing email in another tab)."

RootNotes will treat the request as authentic. Mitigations external:

- Browser sandbox / hygiene on operator endpoints
- Short JWT TTL (configurable; default 8h)
- The operator can `POST /auth/logout` to invalidate the cookie
  immediately
- The audit log gives a forensic trail of what the stolen session did

### S8. "Global admin uploads a Python plugin that exfiltrates all credentials."

Partially mitigated. Admin role is currently required to upload plugins;
the plugin system is an intentional code-execution surface by design —
operators can extend the backend with arbitrary logic. Controls:

- **AST scan on upload**: `eval`, `exec`, `__import__`, `compile` → hard
  400 rejection. `subprocess`, `socket`, `ctypes`, `multiprocessing` →
  upload warning logged and returned in the response.
- **HMAC plugin signing** (opt-in): if `PLUGIN_SIGNING_KEY` is set, every
  upload requires an `X-Plugin-Signature` header produced by
  `POST /api/admin/modules/sign`. This proves the file went through the
  admin-controlled sign endpoint *as-is* (no post-sign substitution).
  With `PLUGIN_REQUIRE_SIGNATURE=true`, unsigned uploads are rejected 403.
- **Sandbox**: Python 3 standard import isolation is NOT applied — a plugin
  running in the backend process shares the same address space. Hardened
  AST gates are a heuristic, not a sandbox. A determined admin can
  still craft a plugin that passes the gate.

**Residual risk:** admin is assumed trusted for the purposes of this
model. The controls address *accidental* dangerous patterns and
*supply-chain substitution* (file replaced after signing), not a
determined malicious admin. If the admin is untrusted, remove admin
access; no in-process plugin sandbox is planned.

### S9. "Audit log row deleted from DB to erase evidence."

Detectable. Since B9-4, every `log_event()` call:

1. Writes an HMAC-SHA256 fingerprint (`integrity` column) over the
   canonical fields (id, pid, entity, action, label, ts).
2. Appends a JSONL line to `UPLOAD_ROOT/audit/timeline.jsonl` before the
   DB transaction commits.
3. Optionally forwards to an S3/Minio bucket (WORM-capable) configured
   via `AUDIT_S3_BUCKET`.

`GET /api/admin/audit/verify` cross-references DB rows against the JSONL
file. Event IDs present in the file but absent from DB are reported as
`file_only` — a direct signal that a DB row was deleted after the event
was logged.

**Residual risk:** the JSONL file lives on the same host as the database.
A host-root attacker can edit both. For strong non-repudiation, forward
to an S3 bucket with Object Lock (WORM mode) on a separate account.

---

## 6. Out-of-scope (explicit non-goals)

The model deliberately does **not** address:

- **Multi-tenant SaaS deployment.** RootNotes is single-deployment per
  team / engagement. Cross-tenant isolation is not modelled.
- **DoS hardening.** A single backend instance under sustained load
  will degrade. Front-load with a reverse proxy / autoscaler.
- **Client-side data residency.** The browser caches API responses
  per its own policy; we do not pin to `Cache-Control: no-store`
  except where explicitly sensitive.
- **Forensic-grade tamper detection on the audit log.** HMAC integrity
  and JSONL mirroring (B9-4) detect DB-level row deletion and field
  modification. However, the JSONL file and DB reside on the same host;
  a root-level attacker can alter both. Full non-repudiation requires
  S3/Minio WORM configured on a separate account — that configuration
  is operator responsibility, not enforced by the platform.
- **Backups.** Backup strategy and recovery testing are operator
  responsibility. Lose the encryption key, lose the data.

---

## 7. Change log of this document

| Version | Date | Notes |
|---|---|---|
| 0.1 | 2026-05-17 | Initial threat model; corresponds to RootNotes v0.3.x — the C2 multi-framework parity (Adaptix / Mythic / Sliver) and the per-recipient WebSocket broadcast filter / redaction landed in this release |
| 0.2 | 2026-05-21 | Updated for B9-3 (plugin signing + AST hardening), B9-4 (HMAC audit log integrity + JSONL mirror + optional S3 WORM), B6-2/B6-4 (Redis pub/sub in data plane). Added S8 (malicious plugin upload), S9 (DB audit row deletion). Updated trust boundary diagram. Moved audit-log tamper detection from non-goal to partially-addressed. |
