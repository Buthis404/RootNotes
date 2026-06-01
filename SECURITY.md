# Security

This document describes RootNotes' security model: what is protected,
how, and where the limits are. It is the canonical reference for
operators standing the platform up and for anyone reviewing the code.

A companion document, [THREAT_MODEL.md](THREAT_MODEL.md), enumerates
threats by actor and what each one can / cannot do.

---

## 1. What RootNotes protects

RootNotes holds operational data from an active pentest or red-team
engagement. The protected surface is:

| Asset | Why it matters | Where it lives |
|---|---|---|
| **Credentials** (passwords, NTLM hashes, Kerberos tickets, SSH keys) | Direct authentication material to client systems | `creds` table, encrypted |
| **Notes tagged confidential** | Free-form text that may contain undisclosed findings, victim names, operational details | `notes.content` if tag ∈ {confidential, secret, sensitive, opsec, restricted}, encrypted |
| **Loot text artifacts** (extracted hashes, secrets, config snippets) | Same risk class as credentials | `loots.value` for non-file artifacts, encrypted |
| **C2 operator material** (Adaptix tokens, Mythic apitokens, Sliver operator config JSON) | Whoever holds them controls live attacker infrastructure | `global_settings.c2_integrations`, encrypted token+password fields |
| **Uploaded artifact files** (NTDS dumps, ZIP archives, screenshots) | Often contain the most damaging raw material | `data/uploads/`, **Fernet-encrypted** on filesystem (new uploads); old files remain plaintext |
| **Findings, host inventory, network maps** | Aggregated picture of the engagement; valuable to anyone reconstructing it | PostgreSQL, plaintext |
| **Audit log** (`timeline_events` with `entity="audit"`) | Forensic evidence of who-saw-what | PostgreSQL + HMAC fingerprint per row + append-only JSONL mirror |

---

## 2. Whom RootNotes protects against

RootNotes assumes a **trusted internal network** deployment. The model
defends against:

- **Curious or unprivileged platform users.** A `viewer` cannot see
  credential plaintexts. An `auditor` cannot see credentials at all.
  Permission gates exist at REST endpoints AND at the WebSocket
  broadcast layer (per-recipient filtering + field redaction).
- **Cross-project leakage.** A user who is a member of project A but
  not project B cannot list, read, or search project B's data. The
  same gate covers WebSocket subscriptions.
- **Casual database access at rest.** A snapshot of the PostgreSQL
  volume alone does not yield credential plaintexts — they are
  encrypted with Fernet (AES-128-CBC + HMAC-SHA256).
- **Forgotten audit trail.** When secrets are decrypted for use
  (list endpoint, host actions panel, bulk exec, C2 exec, project
  export), an `audit/...` event is written to the timeline with
  the actor, the cred id, and the context (`bulk_exec`, `c2_exec`,
  `validate`, `export_with_secrets`, `read_credential_secrets`).

---

## 3. What RootNotes does NOT protect against

These are explicit non-goals. If your threat model includes them,
RootNotes alone is insufficient.

- **Filesystem-level compromise of the host.** The Fernet key lives
  on the same machine as the database (`/data/secret.key`, mode 0600,
  generated on first start if `ENCRYPTION_KEY` is unset). An attacker
  with FS read on the data volume has both the ciphertext and the key.
  See [§4](#4-encryption) — set `ENCRYPTION_KEY` via your secret
  manager to break this coupling.
- **Loot file content (legacy).** Files uploaded **before** the
  `file_encrypted` migration (`loots.file_encrypted=FALSE`) remain
  plaintext on the filesystem. Files uploaded after that migration are
  Fernet-encrypted at rest. Only the REST download endpoint is auth-gated
  in both cases.
- **Insider abuse of privileged roles.** A project `owner` or `editor`
  with legitimate `credentials.read_secret` permission has plaintext
  access. The audit log records what they viewed; it does not
  prevent the view.
- **Network exposure.** RootNotes assumes you do not put it on the
  public internet. The `/api/auth/login`, `/api/search`, and webhook
  endpoints are rate-limited (SlowAPI, 5 req/min per IP). There is no
  CAPTCHA and no IP allow-list module — those belong in your reverse
  proxy.
- **Side channels.** Timing, traffic-volume, or log-size inference is
  not mitigated.
- **Browser / endpoint compromise of an authorized operator.** If
  the operator's session token is stolen via XSS in another tab, an
  in-browser tool, or local malware, RootNotes treats the request
  as authentic.
- **Supply-chain compromise.** RootNotes uses upstream Python and JS
  packages with no SBOM verification. We pin versions; we do not
  verify reproducible builds.

---

## 4. Encryption

### Algorithm

Symmetric authenticated encryption via `cryptography.fernet.Fernet`:
- AES-128 in CBC mode for confidentiality
- HMAC-SHA256 over the ciphertext for integrity
- Random IV per encryption

Implementation: [`backend/app/core/crypto.py`](backend/app/core/crypto.py).

Ciphertext storage convention: encrypted values are prefixed with
`__enc__:` so the runtime can distinguish them from legacy plaintext
during the transition. `decrypt_str()` returns legacy values unchanged.

### What is encrypted

| Field | Encrypted? | Notes |
|---|:-:|---|
| `creds.secret` | ✅ | password / NTLM / ticket / SSH key |
| `notes.content` | ✅ conditional | only when the note has a tag in `{confidential, secret, sensitive, opsec, restricted}` |
| `loots.value` | ✅ for non-file artifacts | text field for "hash" / "secret" / "text" loot types |
| `loots` uploaded files | ✅ new uploads | `file_encrypted=TRUE` rows are Fernet-encrypted on disk; pre-migration files remain plaintext |
| `global_settings.c2_integrations[].token` and `.password` | ✅ | per-integration |
| Everything else (hosts, findings, host activities, jobs, network map, timeline, etc.) | ❌ | considered operationally needed in plaintext |

### Key management

The single Fernet key is resolved in this order:

1. `ENCRYPTION_KEY` environment variable (recommended for production)
2. `/data/secret.key` on disk (chmod 0600), persisted across container
   restarts
3. Auto-generated and written to (2) on first start

**Strong key management requires (1):** inject the key via your secret
manager (Vault, sops, Kubernetes Secret) and do not let it land on the
data volume. Without (1), an attacker with read on `/data` has both
the encrypted database and the key — encryption-at-rest becomes
encryption-at-rest-for-people-without-the-volume only.

**JWT secret** is separate from the encryption key:

- `JWT_SECRET` env variable (HS256 signing key)
- If unset or weak, the runtime attempts to generate one and persist it to
  `/data/.jwt_secret`
- If `/data` is not writable, startup continues but the generated secret is not
  persisted; the next rebuild or restart may invalidate sessions. Set
  `JWT_SECRET` explicitly in `.env` or your secret manager for any persistent
  deployment.

---

## 5. RBAC

Two layers: a **global role** on every user, and a **project role**
per project membership.

### Global role (`User.role`)

| Role | What they can do |
|---|---|
| `admin` | Manage users, system modules, global C2 integrations; bypass project-level RBAC entirely (admin-bypass in `_evaluate()`); **access is audited** — see §5.1 |
| `user` | Normal user; gated by per-project roles |
| `viewer` _(legacy)_ | Same scope as `user` but blocked from all non-GET requests by middleware. **Naming conflict**: this global `viewer` shares the string `"viewer"` with the per-project `MemberRole.VIEWER`. Prefer creating `user` accounts with project-level `viewer` membership instead |

> **Note on global `viewer`:** The global role predates project-level RBAC. It exists for backwards-compatibility. New deployments should use `user` + project membership. The `is_global_viewer()` helper in `core/deps.py` centralises this check.

### §5.1 Admin access auditing

When a `admin` user accesses a project endpoint **without project membership**
(i.e., full bypass), an `audit/admin_bypass_access` event is written to the
project's `timeline_events` table. This record:

- Is visible in the project timeline to project members
- Is committed immediately, independently of the main request transaction
- Includes: actor username, user ID, and the permission that was checked

Access via project membership (admin who is also an `owner`/`editor` etc.)
is **not** audited by this mechanism — it follows normal per-role rules.

Endpoints guarded by `require_admin`:
- User CRUD (`admin.py`)
- Module on/off switches (`system_modules.py`)
- **Unscoped C2 integrations** (those without `project_ids`) —
  scoped C2 integrations can be managed by their project owners
  (see §5.4)

### Project role (`ProjectMember.role`)

Seven roles. Source of truth: [`backend/app/core/permissions.py`](backend/app/core/permissions.py).

| Role | Read everything | Create / Update | Delete | Manage members | View secrets | Apply topology |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| `owner` | ✅ | ✅ | ✅ | ✅ + transfer ownership | ✅ | ✅ |
| `admin` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `editor` | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ |
| `operator` | ✅ | ✅ (limited) | partial | ❌ | ✅ | preview only |
| `viewer` | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `auditor` | ✅ (no creds) | ❌ | ❌ | ❌ | ❌ | ❌ |

### Permission namespaces

Every protected operation maps to a permission string. Namespaces:

`project`, `hosts`, `credentials`, `findings`, `notes`, `loot`,
`network`, `topology`, `reports`, `timeline`, `scopes`, `attack_paths`,
`command_outputs`, `checklist`, `objectives`, `search`, `kb`,
`playbooks`, `jobs`, `pivots`, `webhooks`, `scans`.

Two-level credential access deserves a specific call-out:

- `credentials.read` — see that a cred exists; see username, host,
  domain, type, cracked-state. **Secret is always returned as `""`**.
- `credentials.read_secret` — see the decrypted secret. The list
  endpoint writes an `audit/read_credential_secrets` event whenever
  it returns at least one decrypted secret.

### Enforcement points

The same gate is consulted in three places. Bypassing one does not
bypass the others.

1. **REST endpoint handlers** call
   `check_pid_access(db, pid, user, "<permission>")` (or
   `check_object_access` / `user_has_permission`). Returns 403 on
   refusal, 404 when user is not a project member at all.
2. **WebSocket broadcast** ([`backend/app/ws.py`](backend/app/ws.py))
   filters per recipient against `_ENTITY_POLICY`. If the recipient
   lacks the entity's `read` permission, the event is dropped. If
   the recipient has `read` but not a redact permission (e.g.
   `credentials.read_secret`), the sensitive field is replaced with
   `""` in the per-recipient payload. Global admins bypass.
3. **`require_admin` dependency** at the FastAPI layer for endpoints
   that have no project context (user CRUD, module toggles, unscoped
   C2 CRUD).

### Project-scoped C2 integrations

Since v0.3+, a project `owner` can register their own C2 integration
(Adaptix / Mythic / Sliver) bound to one or more projects they own.
Constraints:

- Non-admins must supply `project_ids`; an integration without
  `project_ids` (global) remains admin-only to create / edit / delete.
- A non-admin cannot widen `project_ids` to include a project they
  don't own, nor empty it (which would promote the integration to
  global).
- Visibility (list endpoint): admins see all; project members see
  integrations bound to their projects.

---

## 6. Audit log

Audit events live in the same `timeline_events` table as ordinary
project events, distinguished by `entity = "audit"`. Coverage:

| Event | When |
|---|---|
| `read_credential_secrets` | A user with `credentials.read_secret` lists credentials and at least one secret is returned. Also written by `get_host_actions` when the panel reveals project creds matched to a host |
| `secret_used_bulk_exec` | A credential is bound to a `bulk_exec` job |
| `secret_used_validate` | A credential is bound to a `validate_cred` job |
| `secret_used_c2_exec` | A credential is substituted into a C2 exec command line |
| `export_with_secrets` | A project export is generated and the exporter has `credentials.read_secret` |
| `webhook_token_regenerated` | A project webhook token is rotated |
| `note_viewed` (confidential), `loot_viewed` (sensitive) | Confidential note content / sensitive loot value is decrypted for display |

Audit events are visible in the project timeline; they are not deleted
when an entity is deleted, so the trail survives cleanup.

| `admin_bypass_access` | A global admin accesses a project endpoint without project membership (bypass audit — see §5.1) |

What is **not** in the audit log:
- WebSocket event deliveries
- Read endpoints that return only metadata (e.g. host list)
- Failed access attempts (403 / 404) — these go only to application logs

### §6.1 Audit log hardening (B9-4)

Since v0.4, every `log_event()` call uses three independent persistence
channels:

| Channel | Where | Tamper-detectable | Immutable by default |
|---|---|:-:|:-:|
| DB row (`timeline_events`) | PostgreSQL | ✅ via HMAC `integrity` field | ❌ DB admin can `DELETE` |
| JSONL file | `UPLOAD_ROOT/audit/timeline.jsonl` (O_APPEND) | — | ❌ host-root can edit |
| S3/Minio object | configured bucket, one object per event | — | ✅ with Object Lock / WORM |

**HMAC integrity:** when `AUDIT_INTEGRITY_KEY` is set, each event gets a
`sha256=<hex>` fingerprint over the canonical fields (id, pid, entity,
action, label, ts). `GET /api/admin/audit/verify` checks all stored rows,
reporting:

- `tampered` — event IDs whose stored hash no longer matches recomputed
- `unverified` — rows created before B9-4 (no integrity field)
- `file_only` — event IDs in the JSONL file but absent from DB (indicates
  a row was deleted after it was logged)

**To enable:**

```bash
# Add to .env:
AUDIT_INTEGRITY_KEY=$(openssl rand -hex 32)
AUDIT_LOG_DIR=/data/uploads/audit          # default

# Optional S3/Minio WORM forward:
AUDIT_S3_BUCKET=my-worm-bucket
AUDIT_S3_ENDPOINT_URL=https://minio.internal
```

---

## 7. AI chat

RootNotes includes an optional AI chat feature
(`POST /api/projects/{pid}/ai/chat`).

### What data is sent to the LLM provider

When a chat request is made, the system prompt sent to the configured
LLM provider includes:

- **Counts only** of project entities (host count, credential count,
  finding count, note count, loot count, scope count, attack-step count)
- The full **conversation history** submitted by the operator in the
  request body

**Sensitive values are not included** in the system prompt — no
credential secrets, no note content, no uploaded file content. The AI
agent can **call tools** (read hosts, findings, notes, creds metadata),
so the operator's questions and AI tool-call results may include
project entity names, hostnames, IPs, and finding titles.

### Privacy and opsec implications

- All chat messages and tool-call contents are transmitted to the
  configured external LLM provider (OpenAI-compatible API). The
  provider may log or train on this data per their own terms of service.
- Do not include client names, unreported vulnerabilities, or other
  sensitive engagement details in AI chat prompts if your engagement
  agreement prohibits data sharing with third parties.
- For air-gapped or sensitive engagements: use a locally-hosted
  OpenAI-compatible endpoint (e.g. Ollama, vLLM) configured via
  `PUT /api/ai/config`.

### Kill switch

The AI module can be disabled globally by an admin via the system
modules toggle (`PUT /api/system-modules` with `{"ai": false}`). When
disabled, all `/api/projects/{pid}/ai/*` endpoints return 403.

### Configuration

`GET /api/ai/config` (admin) — returns current provider list with API
keys masked (last 4 chars shown). `PUT /api/ai/config` (admin) — save
provider configuration. Treat the AI provider configuration as sensitive
application data and review the current implementation before using external
providers on restricted engagements.

---

## 8. Webhook HMAC authentication

RootNotes supports HMAC-SHA256 signature verification on incoming webhook
requests (Cobalt Strike, Sliver, Havoc, custom). This feature is **disabled
by default** — if `WEBHOOK_HMAC_SECRET` is not set, any request that knows
the project webhook URL token is accepted without authentication.

### Risk

Without HMAC, an attacker who learns a project's webhook URL can inject
arbitrary host/credential/finding data into the project. Webhook tokens
are UUIDs (unguessable), but they may appear in C2 configuration files,
logs, or network captures.

### Mitigation

Set `WEBHOOK_HMAC_SECRET` in your environment before exposing webhooks to
untrusted networks:

```bash
# Generate a 32-byte hex secret:
openssl rand -hex 32
# Then add to .env:
WEBHOOK_HMAC_SECRET=<output>
```

When set, every incoming `POST /api/webhooks/{token}` request **must**
include an `X-Hub-Signature-256: sha256=<hmac>` header computed over the
raw request body with the shared secret. Requests without a valid header
are rejected with 403.

**The `GET /api/projects/{pid}/webhook` endpoint** returns
`"hmac_required": true/false` so operators can verify the current
configuration.

Pre-deployment checklist item: ensure `WEBHOOK_HMAC_SECRET` is set in
any deployment where the webhook endpoint is reachable from hosts you do
not fully control.

---

## 9. ENCRYPTION_KEY rotation

### Why rotation is risky without a migration tool

Fernet keys are non-rotatable without re-encrypting the data. If you
update `ENCRYPTION_KEY` in your environment without first re-encrypting all
stored ciphertexts, the following data becomes permanently unreadable:

- All credential secrets
- All confidential/restricted note contents
- All sensitive loot values (hashes, secrets, text artifacts)
- All uploaded loot files marked `file_encrypted=True`
- C2 integration token and password fields

**Backups** created with the old key are also unreadable under the new key
unless you decrypt them first.

### Rotation procedure

Use the bundled `backend/scripts/rekey.py` CLI:

```bash
# 1. Generate a new Fernet key
NEW_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
echo $NEW_KEY   # save this somewhere safe

# 2. Dry-run: count affected rows without writing
OLD_KEY=<current_key> NEW_KEY=$NEW_KEY \
  python3 backend/scripts/rekey.py --dry-run

# 3. If counts look correct, run the actual migration
#    (do this with the API stopped or in maintenance mode)
OLD_KEY=<current_key> NEW_KEY=$NEW_KEY \
  python3 backend/scripts/rekey.py

# 4. Update ENCRYPTION_KEY in your environment / secret manager
# 5. Restart the backend container
```

The script also accepts positional arguments:
`python3 rekey.py <old_key> <new_key> [--dry-run]`

Required env vars for DB connection: `DATABASE_URL` (or
`DB_HOST` / `DB_PORT` / `DB_NAME` / `DB_USER` / `DB_PASSWORD`).
`UPLOAD_ROOT` defaults to `/data/uploads`.

### What the script re-encrypts

| Source | Column / field |
|---|---|
| `credentials` | `secret` |
| `notes` | `content` (only `__enc__:` prefixed rows) |
| `loots` | `value` (only `__enc__:` prefixed rows) |
| `loots` | on-disk files where `file_encrypted=TRUE` |
| `global_settings` | `c2_integrations[*].token` and `.password` |

### Backup first

Always take a database dump and a copy of `data/uploads/` **before**
running rekey. Fernet decryption with the wrong key raises `InvalidToken`
and the script will exit with a non-zero status — original data is
preserved in that case because the script uses a single transaction.

---

## 10. Notification opsec (Telegram / Slack)

RootNotes can dispatch alerts to Telegram and Slack via the notification
module. This requires **outbound HTTP/HTTPS to external internet hosts**
from the machine running the backend container.

### Opsec implications

| Risk | Detail |
|---|---|
| **Traffic leakage** | Alert content (finding titles, severity, host names) is transmitted to `api.telegram.org` or `hooks.slack.com`. In air-gapped or restricted networks, this traffic may be visible to network monitoring. |
| **Provider logging** | External providers may log message content per their terms of service. Do not include client names or unreported vulnerability details in finding titles if your engagement agreement prohibits sharing with third parties. |
| **DNS leakage** | Even if HTTPS is proxied, the DNS lookup for `api.telegram.org` is observable on the local network. |
| **Air-gapped conflict** | If the deployment machine has no outbound internet access, notification delivery fails silently with an error in application logs — no retries are queued. |

### Recommendations

- For air-gapped or VPN-isolated deployments: disable the notification
  module via `PUT /api/system-modules` with `{"notifications": false}`.
- Use a self-hosted webhook relay (mattermost, Matrix, local SMTP) and
  configure RootNotes' custom webhook integration instead.
- Treat finding titles and host names as potentially sensitive — keep
  them opsec-safe in case they appear in notification bodies.

---

## 11. Plugin system security (B9-3)

RootNotes supports server-side Python plugins (`PUT /api/admin/modules`).
Plugins execute in-process — a loaded plugin shares the backend's memory
and can call any Python API. Controls address supply-chain substitution
and accidental dangerous patterns, not a determined malicious admin.

### AST validation on upload

Every uploaded plugin is scanned at the AST level before it is saved:

| Pattern | Disposition |
|---|---|
| `eval`, `exec`, `__import__`, `compile` | Hard 400 rejection — upload refused |
| `subprocess`, `socket`, `ctypes`, `multiprocessing` | Upload proceeds; warning returned in response and logged |

### HMAC plugin signing (opt-in)

When `PLUGIN_SIGNING_KEY` is set:

1. Admin calls `POST /api/admin/modules/sign` with the plugin source.
   The endpoint runs the same AST validation and returns a
   `sha256=<hex>` HMAC over the content.
2. Admin uploads via `PUT /api/admin/modules/{name}` with the
   `X-Plugin-Signature` header.
3. The upload endpoint verifies the header before saving.

With `PLUGIN_REQUIRE_SIGNATURE=true`, unsigned uploads are rejected 403.
This ensures files are not substituted between the sign and upload steps.

**Residual risk:** the signing endpoint and the DB run on the same host.
A host-root attacker can replace the key. Plugin signing addresses
casual supply-chain substitution and CI/CD pipeline hygiene, not an
admin-level adversary.

### Configuration

```bash
# .env
PLUGIN_SIGNING_KEY=$(openssl rand -hex 32)
PLUGIN_REQUIRE_SIGNATURE=true   # enforce; default false
```

---

## 12. Reporting a vulnerability

Open an issue on GitHub for non-sensitive reports. For sensitive
disclosures, email the maintainer privately (see the repository
README for contact). Please include:

- Affected version (`git rev-parse HEAD` or release tag)
- A minimal reproducer
- The threat actor profile from `THREAT_MODEL.md` that you believe
  applies

We aim to acknowledge within 5 business days. Coordinated disclosure
windows are negotiated case-by-case.

---

## 13. Pre-deployment checklist

Before pointing real engagement data at a RootNotes instance:

- [ ] `JWT_SECRET` set to a long random value via env / secret manager
- [ ] `ENCRYPTION_KEY` set the same way; not relying on auto-generated
      `/data/secret.key`
- [ ] `DB_PASSWORD` and `ADMIN_PASSWORD` rotated from defaults
- [ ] Reverse proxy in front (TLS termination, rate limit, IP allow-list)
- [ ] `/data/uploads/` on a volume with at-rest encryption (e.g.
      LUKS, cloud-managed disk encryption)
- [ ] Default `admin` user has been disabled or had its password
      rotated after the first real operator account is created
- [ ] Backup strategy for the database — including the
      `ENCRYPTION_KEY`, otherwise backups are unrecoverable
- [ ] Monitor `timeline_events` where `entity="audit"` for anomalies
      (off-hours mass exports, repeated secret reads, etc.)
- [ ] `WEBHOOK_HMAC_SECRET` set if any webhook endpoint is reachable
      from hosts you do not fully control (see §8)
- [ ] `ENCRYPTION_KEY` rotation procedure documented; `backend/scripts/rekey.py`
      available for key migration (see §9)
- [ ] Notification module disabled (`notifications: false` in system-modules)
      or configured with a self-hosted relay if operating in an air-gapped
      or VPN-isolated environment (see §10)
- [ ] `AUDIT_INTEGRITY_KEY` set via env / secret manager; run
      `GET /api/admin/audit/verify` after first start to confirm HMAC
      is being applied to new events (see §6.1)
- [ ] `AUDIT_S3_BUCKET` configured with Object Lock if you need
      host-root-resistant audit immutability (see §6.1)
- [ ] `PLUGIN_SIGNING_KEY` and `PLUGIN_REQUIRE_SIGNATURE=true` set if
      you run server-side plugins in a team environment where plugin
      uploads should be signed before deployment (see §13)
