# RootNotes — Implementation Plan

## Purpose

This is the current implementation roadmap based on the actual codebase state.

## Guiding Chain

`connectors -> jobs -> playbooks -> topology -> evidence/reporting`

---

## Stage 1. Finish orchestration runtime

Status: `Done`

- connector-backed jobs across scans, topology, playbooks, C2 sync, and C2 live execution
- retry and rerun behavior for major queued job flows
- shared job metadata with connector, operation, scope, and related-entity linkage
- playbook run detail view with expandable step list and result metrics
- live playbook run sync via WebSocket (no polling)
- job filtering by status / type / connector_key / playbook_run_id / free text
- parent-child linkage: jobs carry playbook_run_id; Jobs view filters by run

---

## Stage SR. Structured Result Schema

Status: `Done`

After every queued job, `result_json["structured"]` is populated:

- `ok`, `auth_success`, `access_role`, `summary`
- `hosts_affected`, `creds_affected`, `host_changes`, `cred_changes`
- `finding_candidates`, `graph_updates`, `counts`

Normalizer in `core/result_normalizer.py` handles: `attacker_ssh`, `netexec`, `cred_validate`, `nmap`, `nuclei`, `httpx`, `ffuf`, `c2 sync`, `topology`.

Finding candidates surfaced automatically:
- `(Pwn3d!)` → critical "pwned_host"
- `local_admin`/`domain_admin` achieved → high "privileged_access"
- credential valid on ≥3 hosts → high "valid_on_many_hosts"

Playbook branching uses structured keys via dot notation:
- `structured.auth_success eq true`
- `structured.access_role eq local_admin`
- `structured.counts.hosts_valid gte 1`

---

## Stage RW. Result Writeback

Status: `Done`

`core/writeback.py` automatically enriches project state after every queued job:

- **nmap** → auto-tag hosts by discovered ports (dc, ldap, smb, web, ssh, rdp, winrm, mssql…)
- **netexec** → detect `(Pwn3d!)` → set `host.status = "compromised"`, add `pwned` tag; link cred to host
- **httpx** → add `web` tag to probed host
- **attacker_ssh exec** → link `cred_id` to `host_id` on success

---

## Stage FA. Fan-out playbooks (Batch Run)

Status: `Done`

- `POST /api/projects/{pid}/playbooks/{id}/batch-run`
- host filter: explicit host_ids, tag overlap, status filter
- parallelism: 1–10 concurrent runs via asyncio.Semaphore
- `{target}` / `{domain}` / `{username}` / `{password}` / `{hash}` substitution
- auth fallback for netexec steps
- UI: Batch Run tab with host selector, tag filter, parallelism selector
- `batch_id` stored in PlaybookRun.request_json for grouping

---

## Stage AD. AD Workflow Playbooks

Status: `Done`

Built-in playbooks:

- `ad-ldap-enum` — NetExec LDAP users/groups/computers/policy
- `ad-spray-smb` — SMB password spray with continue-on-success
- `ad-kerberoast` — impacket-GetUserSPNs TGS extraction
- `ad-asreproast` — impacket-GetNPUsers AS-REP hash capture
- `ad-full-recon` — Nmap → LDAP → Kerberoast → topology (4 steps)

Step templates added for custom playbook builder:
- `attacker_ssh:kerberoast`, `attacker_ssh:asreproast`, `attacker_ssh:ldap_dump`
- `netexec:ldap_enum`, `netexec:spray_smb`

---

## Stage FT. Full-text Job Output Search

Status: `Done`

- `output_search` query param in `GET /api/projects/{pid}/jobs` — SQL `ilike` on output
- Debounced search input in JobsView (400ms)
- Auto-expand matched job rows; highlight matching lines; count badge

---

## Stage GR. Attack Graph Improvements

Status: `Done`

- Attack Graph renders persisted `Network.edges_json` access edges (not only credential links)
- `domain_admin` edge type: red `#e8574a`, solid (verified) or dashed (inferred)
- Edge types consistent between Network Map and Attack Graph
- Attacker-root reachability: `reachable`, `reachable_via_verified_path`, `distance`, `verified_distance`
- Interactive canvas: drag-and-drop nodes, localStorage persistence
- Side panel: linked creds, findings, access edges with confidence/state/reason
- Pivot observations: SSH collection of chisel/ligolo routes → network edges

---

## Stage SEC. Security Hardening

Status: `Done`

- Credentials encrypted at rest (Fernet AES-128)
- Confidential note content encrypted at rest (tags: confidential/secret/sensitive/opsec/restricted)
- Sensitive text loot values encrypted at rest
- Read audit events for credential secrets, confidential notes, sensitive loot, file downloads
- RBAC: viewer/auditor cannot read credential secrets
- `ENCRYPTION_KEY` in `.env` persists key across container rebuilds
- File downloads: Range request support (206 Partial Content), correct Content-Type from DB, streaming

---

## Stage EX. Encrypted Export

Status: `Done`

- Project export auto-detects if credentials have non-empty secrets
- If yes: ZIP encrypted with AES-256 via `pyzipper`
- Password auto-generated (`secrets.token_urlsafe(16)`) or provided via `?password=` param
- Password returned in `X-Zip-Password` response header
- Frontend shows password in alert after download
- `Content-Disposition` uses RFC 5987 (`filename*=UTF-8''...`) — supports Cyrillic and other non-ASCII project names

---

## Stage 2. Improve playbook authoring

Status: `Active`

Done:
- visual builder, validation, step templates
- result-aware branching with autocomplete
- duplicate step (Dup button), move step up/down (↑↓)
- step number label

Recommended next:
1. saved parameter presets per connector
2. step search / jump-to in long playbooks
3. export/import of playbooks as portable library assets
4. major UX pass on long-form playbook authoring and review

---

## Stage 3. Improve graph semantics

Status: `Active`

Done:
- smart-build multi-layer topology
- Attack Graph edge unification (credential + access + path)
- domain_admin edge type (red)
- reachability computation
- pivot observations + SSH collection

Recommended next:
1. trust-zone and segment modeling (DMZ, internal, management)
2. C2 live sessions → c2_session edges in graph
3. UI to promote inferred → verified edges
4. session-to-graph fusion from C2 state
5. route-aware pivot graph semantics (SOCKS, tunnels, routed segments)
6. AD-aware edge building from SharpHound/BloodHound data

---

## Stage 4. Expand domain-aware identity model

Status: `Started`

Done:
- domain alias-aware matching
- cross-domain host-link protection
- domain-aware credential validation
- credential × host access matrix (heatmap view)

Recommended next:
1. explicit project domain inventory
2. editable alias sets per project
3. domain analytics and reuse views

---

## Stage 5. Expand connector catalog

Status: `In progress`

Done:
- `httpx` — HTTP probe, discovers live web services
- `ffuf` — web content discovery, findings for discovered paths
- Adaptix live operator tasking

Recommended next:
1. `subfinder` / `amass`
2. `hashcat` / `john`
3. Metasploit integration only after transport/runtime stabilization

---

## Stage 6. Deepen live C2 operations

Status: `Started`

Done:
- per-project C2 integration visibility
- live session inventory per project
- Adaptix host-matched live actions from Hosts and Network Map
- Adaptix BOF catalog pull and normalization
- RootNotes and C2 credential substitution
- polling-based interactive CLI for Adaptix agents
- `c2_exec` jobs + `host_activity` recording

Recommended next:
1. extend live tasking to Cobalt Strike and Sliver
2. improve BOF parameter fidelity
3. richer task status lifecycle and execution history
4. artifact and loot capture from live task output
5. evaluate websocket/streaming transport for interactive shells

---

## Stage 7. Operator automation packs

Status: `Started`

Done:
- shared host actions from Hosts and Network Map
- credential-aware live command rendering
- quick operation templates for common host actions
- bulk credential-driven replay across selected hosts (Bulk Run)
- automatic state updates from successful bulk runs
- transport fallback: attacker SSH cycles through all assigned global targets

Recommended next:
1. expand operation templates
2. deepen credential-driven packs
3. mass validation and replay across filtered host sets
4. session-aware fallback between live agent, attacker SSH, and credential-based execution
5. AD-focused workflow packs

---

## Stage 8. Strengthen tests

High-priority technical requirement.

Recommended:
1. playbook validation and branching
2. queued job retry/rerun
3. credential validation jobs
4. domain alias matching and link restrictions
5. topology edge metadata behavior
6. Adaptix BOF normalization and live task polling
7. project-scoped C2 visibility and host action access control
8. operation template rendering and credential substitution
9. graph and export load testing

---

## Stage 9. Reporting and evidence

Recommended later:
1. artifact hashing and deduplication
2. richer evidence linkage
3. HTML/PDF/DOCX export
4. better attack-path and topology export blocks
5. encrypted portable exports for KB/snippets/playbooks

---

## Stage 10. Knowledge Asset Portability

Recommended later:
1. export/import for KB articles
2. export/import for custom snippets
3. export/import for playbooks
4. versioned knowledge packs (project/global)

---

## Stage 11. Timeline Rollback

Recommended later:
1. project snapshots tied to timeline checkpoints
2. rollback with return/redo semantics
3. scoped rollback for graph/manual edges/notes/findings

---

## Stage 12. MITRE And Attack Modeling

Recommended later:
1. MITRE matrix/table inside the product
2. map major attacks and workflow templates to ATT&CK
3. auto-suggest techniques in Attack Path authoring
4. group/vector-aware attack modeling

---

## Stage 13. Transport Proxying

Recommended later:
1. SSH through proxy / jump host / SOCKS
   - current status: transport-layer `jump` and authenticated `socks5` support implemented for attacker SSH targets
2. separate execution-layer proxying from attacker host
   - current status: scan-time execution source selector now models `attacker host` vs `pivot listener` instead of hiding scan-origin choice in attacker-host settings
3. transport selection aware of pivots and routes
   - current status: initial route-aware ranking implemented for scans and attacker-exec when global attacker targets are auto-selected
4. collector workflows for pivot-aware execution
5. richer multi-hop transport chains and scanner-specific jump integration

---

## What To Avoid

1. disconnected new tabs without orchestration value
2. overbuilding plugin abstraction before builtin flows stabilize
3. delivery-grade reporting before evidence workflow is stronger
