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
| **Uploaded artifact files** (NTDS dumps, ZIP archives, screenshots) | Often contain the most damaging raw material | `data/uploads/`, **plaintext on filesystem** |
| **Findings, host inventory, network maps** | Aggregated picture of the engagement; valuable to anyone reconstructing it | PostgreSQL, plaintext |
| **Audit log** (`timeline_events` with `entity="audit"`) | Forensic evidence of who-saw-what | PostgreSQL, plaintext |

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
- **Loot file content.** Uploaded files (`data/uploads/`) are stored
  plaintext on the filesystem. Only their REST download endpoints are
  auth-gated. If you upload a 200MB NTDS dump it sits on disk in the
  clear.
- **Insider abuse of privileged roles.** A project `owner` or `editor`
  with legitimate `credentials.read_secret` permission has plaintext
  access. The audit log records what they viewed; it does not
  prevent the view.
- **Network exposure.** RootNotes assumes you do not put it on the
  public internet. There is no rate-limit-tuning, no CAPTCHA, no
  IP allow-list module — those belong in your reverse proxy.
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
| `loots.value` | ✅ for non-file artifacts | files are stored unencrypted on disk; only the text field for "hash" / "secret" / "text" loot types is encrypted |
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
- If unset or weak, the runtime generates one and persists it to
  `/data/.jwt_secret`
- The warning printed on startup is intentional — fix it before
  exposing the service.

---

## 5. RBAC

Two layers: a **global role** on every user, and a **project role**
per project membership.

### Global role (`User.role`)

| Role | What they can do |
|---|---|
| `admin` | Manage users, system modules, global C2 integrations; bypass project-level RBAC entirely (admin-bypass in `_evaluate()`) |
| `member` | Everything else; gated by per-project roles |

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

What is **not** in the audit log:
- WebSocket event deliveries
- Read endpoints that return only metadata (e.g. host list)
- Failed access attempts (403 / 404) — these go only to application logs

---

## 7. Reporting a vulnerability

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

## 8. Pre-deployment checklist

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
