"""Seed a test project with realistic load for performance benchmarking.

Generates:
  - 1 project ("PerfTest-1k")
  - 1000 hosts (varied status, role, os, ports)
  - 500 creds (local + domain, plain/ntlm)
  - 200 findings (all severities)
  - 30 scope entries (CIDR + domain)
  - 50 loot rows (no actual files)
  - 3000 host_activities (history per host)
  - 1500 jobs (varied status, with request_json playbook_run_id)
  - 5000 timeline events (mixed entities)
  - 1 network with 500 nodes + 800 edges

Run from inside the backend container:
  docker compose exec backend python -m seed_perf_test

The script is idempotent on the project ID — re-running deletes the
old project (CASCADE wipes everything) and inserts fresh.
"""
from __future__ import annotations

import random
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Make `app.*` importable when run directly inside the container.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.database import SessionLocal  # noqa: E402
from app import models  # noqa: E402

PROJECT_ID = "perftest1k"
PROJECT_NAME = "PerfTest-1k"
RNG_SEED = 42

random.seed(RNG_SEED)


def _ts(offset_minutes: int = 0) -> str:
    return (datetime.now(UTC) - timedelta(minutes=offset_minutes)).strftime("%Y-%m-%d %H:%M")


def _rand_ip() -> str:
    return f"10.{random.randint(0, 99)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


HOST_OS = ["Windows Server 2019", "Windows 10", "Windows 11", "Ubuntu 22.04", "Debian 12", "CentOS 7", "Alpine 3.18"]
HOST_ROLES = ["unknown", "workstation", "server", "dc", "web_server", "database", "jump_host", "external"]
HOST_STATUS = ["unknown", "alive", "scanned", "access", "pwned"]
PORTS_POOL = ["22", "80", "443", "445", "3389", "5985", "21", "53", "88", "139", "389", "636", "1433", "3306", "5432", "8080", "8443", "9200"]
SERVICES_POOL = ["ssh", "http", "https", "smb", "rdp", "winrm", "ftp", "dns", "kerberos", "netbios", "ldap", "ldaps", "mssql", "mysql", "postgres", "elasticsearch"]
TAGS_POOL = ["nmap", "rescan", "internal", "external", "dmz", "high-value", "patched", "legacy", "honeypot", "pwned"]

CRED_TYPES = ["plain", "ntlm", "kerberos", "key"]
CRED_SERVICES = ["smb", "winrm", "ssh", "ldap", "mssql", "rdp", "http"]

SEVERITIES = ["critical", "high", "medium", "low", "info"]
FINDING_TITLES = [
    "EternalBlue (MS17-010)", "SMB signing disabled", "LDAP anonymous bind",
    "Kerberoasting possible", "Outdated SSH version", "Weak SSL/TLS ciphers",
    "Default credentials", "Open RDP from internet", "PrintNightmare (CVE-2021-34527)",
    "ZeroLogon (CVE-2020-1472)", "Unconstrained delegation", "Pre-Win2k compat group",
    "AS-REP roasting", "ADCS ESC1", "BloodHound path to DA",
]

ACTIVITY_TYPES = ["recon", "scan", "exploit", "postex", "credential_dump", "lateral", "persistence"]

JOB_STATUSES = ["queued", "running", "done", "failed", "cancelled"]
JOB_CONNECTORS = ["nmap", "nuclei", "netexec", "httpx", "ffuf", "attacker_ssh", "donpapi"]

TIMELINE_ENTITIES = ["host", "cred", "finding", "note", "audit"]
TIMELINE_ACTIONS = ["create", "update", "delete", "status"]


def _seed_hosts(db, project_id: str, hosts_n: int) -> tuple[list, list]:
    host_ids: list[str] = []
    host_ips: list[str] = []
    used_ips: set[str] = set()
    hosts_batch = []
    for i in range(hosts_n):
        while True:
            ip = _rand_ip()
            if ip not in used_ips:
                used_ips.add(ip)
                break
        hid = f"hst_{project_id}_{i:05d}"
        host_ids.append(hid)
        host_ips.append(ip)
        hosts_batch.append({
            "id": hid, "pid": project_id, "ip": ip, "ips": [ip],
            "hostname": f"host-{i:05d}.lab.local" if random.random() > 0.3 else "",
            "os": random.choice(HOST_OS),
            "status": random.choices(HOST_STATUS, weights=[10, 30, 30, 20, 10])[0],
            "ports": random.sample(PORTS_POOL, k=random.randint(2, 8)),
            "services": random.sample(SERVICES_POOL, k=random.randint(1, 5)),
            "tags": random.sample(TAGS_POOL, k=random.randint(0, 4)),
            "notes": "" if random.random() > 0.2 else f"Auto-imported host #{i}",
            "domain": "lab.local" if random.random() > 0.5 else "",
            "role": random.choice(HOST_ROLES), "is_attacker": False,
            "import_source": random.choice(["nmap", "manual", "nessus", "import"]),
        })
    db.bulk_insert_mappings(models.Host, hosts_batch)
    db.flush()
    return host_ids, host_ips


def _seed_findings(db, project_id: str, findings_n: int, host_ids: list) -> None:
    hosts_n = len(host_ids)
    findings_batch = []
    for i in range(findings_n):
        findings_batch.append({
            "id": f"fnd_{project_id}_{i:05d}", "pid": project_id,
            "host_id": host_ids[random.randrange(hosts_n)] if random.random() > 0.2 else None,
            "title": random.choice(FINDING_TITLES) + f" (#{i})",
            "severity": random.choices(SEVERITIES, weights=[5, 15, 35, 30, 15])[0],
            "cvss": f"{random.uniform(3.0, 9.8):.1f}",
            "cve": f"CVE-202{random.randint(0, 5)}-{random.randint(1000, 99999)}" if random.random() > 0.4 else "",
            "description": "Auto-generated finding for performance testing.",
            "proof": f"Proof of finding {i} — output snippet here.",
            "recommendation": "Apply vendor patch / harden configuration.",
            "status": random.choice(["open", "candidate", "fixed", "accepted"]),
            "source": random.choice(["manual", "nuclei", "nessus", "nmap"]),
            "ts": _ts(offset_minutes=random.randint(0, 60 * 24 * 7)),
        })
    db.bulk_insert_mappings(models.Finding, findings_batch)
    db.flush()


def _seed_scopes(db, project_id: str, scopes_n: int, host_ids: list) -> None:
    hosts_n = len(host_ids)
    scopes_batch = []
    for i in range(scopes_n):
        scopes_batch.append({
            "id": f"scp_{project_id}_{i:04d}", "pid": project_id,
            "value": f"10.{random.randint(0, 99)}.0.0/16" if random.random() > 0.3 else f"sub{i}.lab.local",
            "scope_type": "cidr" if random.random() > 0.3 else "domain",
            "in_scope": random.random() > 0.1, "description": "Auto",
            "gateway_ip": "", "is_entry": random.random() > 0.85,
            "via_host_id": host_ids[random.randrange(hosts_n)] if random.random() > 0.7 else "",
        })
    db.bulk_insert_mappings(models.Scope, scopes_batch)
    db.flush()


def _seed_jobs(db, project_id: str, jobs_n: int, host_ips: list) -> None:
    fake_run_ids = [f"pbr_{project_id}_{i:04d}" for i in range(50)]
    jobs_batch = []
    for i in range(jobs_n):
        run_id = random.choice(fake_run_ids) if random.random() > 0.4 else ""
        jobs_batch.append({
            "id": f"job_{project_id}_{i:05d}", "pid": project_id,
            "type": random.choice(JOB_CONNECTORS),
            "status": random.choices(JOB_STATUSES, weights=[5, 5, 70, 15, 5])[0],
            "title": f"Auto job #{i}", "target": random.choice(host_ips),
            "command": "nmap -sV", "output": "scan output here", "error_output": "",
            "created_by": "perfbench", "connector_key": random.choice(JOB_CONNECTORS),
            "operation": "scan", "scope_type": "project", "scope_id": "",
            "related_entity_type": "playbook_run" if run_id else "",
            "related_entity_id": run_id, "retry_of_job_id": "",
            "priority": 0, "retry_count": 0, "max_retries": 0,
            "created_at": _ts(offset_minutes=random.randint(0, 60 * 24 * 7)),
            "started_at": "", "finished_at": "",
            "request_json": {"playbook_run_id": run_id} if run_id else {},
            "result_json": {"hosts_created": random.randint(0, 5)},
        })
    db.bulk_insert_mappings(models.Job, jobs_batch)
    db.flush()


def _seed_network_data(db, project_id: str, nodes_n: int, edges_n: int, host_ids: list, host_ips: list) -> None:
    network = models.Network(id=f"net_{project_id}", pid=project_id, name="Main Network")
    db.add(network)
    db.flush()
    node_ids: list[str] = []
    nodes_batch = []
    for i in range(nodes_n):
        host_idx = i % len(host_ids)
        nid = f"nn_{project_id}_{i:05d}"
        node_ids.append(nid)
        nodes_batch.append({
            "id": nid, "network_id": network.id, "pid": project_id,
            "host_id": host_ids[host_idx],
            "x": (i % 25) * 80.0, "y": (i // 25) * 80.0,
            "label": f"host-{host_idx:05d}", "ip": host_ips[host_idx], "ips": [host_ips[host_idx]],
            "type": random.choice(["host", "server", "web", "dc", "workstation"]),
            "status": random.choice(HOST_STATUS),
            "ports": random.sample(PORTS_POOL, k=random.randint(1, 4)),
            "notes": "", "role": random.choice(HOST_ROLES), "os": random.choice(HOST_OS),
            "tags": [], "is_attacker": False,
            "manually_positioned": False, "auto_positioned": True,
            "updated_at": _ts(), "version": 1, "extra_json": {},
        })
    db.bulk_insert_mappings(models.NetworkNode, nodes_batch)
    db.flush()
    edges_batch = []
    for i in range(edges_n):
        a, b = random.sample(node_ids, 2)
        edges_batch.append({
            "id": f"ne_{project_id}_{i:05d}", "network_id": network.id, "pid": project_id,
            "from_node_id": a, "to_node_id": b,
            "style": random.choice(["solid", "dashed"]),
            "type": random.choice(["network", "access", "lateral", "tunnel"]),
            "label": "", "confidence": 1.0, "source": "auto",
            "reason": "", "state": "auto", "verified": False,
            "is_manual": False, "manual_override": False,
            "updated_at": _ts(), "version": 1, "extra_json": {},
        })
    db.bulk_insert_mappings(models.NetworkEdge, edges_batch)
    db.flush()


def seed(db, *, hosts_n=1000, creds_n=500, findings_n=200, scopes_n=30,
         loots_n=50, activities_n=3000, jobs_n=1500, timeline_n=5000,
         nodes_n=500, edges_n=800):
    t0 = time.time()
    log = lambda m: print(f"[{time.time() - t0:6.2f}s] {m}", flush=True)  # noqa: E731

    # Wipe existing test project (CASCADE handles children)
    existing = db.query(models.Project).filter(models.Project.id == PROJECT_ID).first()
    if existing:
        log(f"Deleting existing project {PROJECT_ID}")
        db.delete(existing)
        db.commit()

    log("Creating project")
    project = models.Project(
        id=PROJECT_ID, name=PROJECT_NAME, status="active", ip="", os="Linux",
        added=_ts(), description="Generated by seed_perf_test.py — stress-test fixture",
    )
    db.add(project)
    db.flush()

    log(f"Inserting {hosts_n} hosts")
    host_ids, host_ips = _seed_hosts(db, PROJECT_ID, hosts_n)
    log(f"  → {hosts_n} hosts inserted")

    # ── Creds ────────────────────────────────────────────────────────────────
    log(f"Inserting {creds_n} creds")
    creds_batch = []
    for i in range(creds_n):
        is_domain = random.random() > 0.5
        host_idx = random.randrange(hosts_n)
        base = random.choice(["admin", "administrator", "root", "svc-sql", "svc-backup", "operator", "user"])
        creds_batch.append({
            "id": f"c_{PROJECT_ID}_{i:05d}", "pid": PROJECT_ID,
            "username": f"{base}_{i:04d}", "secret": f"hashed_secret_value_for_cred_{i}",
            "type": random.choice(CRED_TYPES), "service": random.choice(CRED_SERVICES),
            "host": host_ips[host_idx], "domain": "lab.local" if is_domain else "",
            "cracked": random.random() > 0.7, "notes": "",
            "tags": random.sample(["smb", "winrm", "validated", "dpapi", "kerberoast"], k=random.randint(0, 2)),
            "host_ids": [host_ids[host_idx]] if random.random() > 0.5 else [],
            "is_domain": is_domain,
        })
    db.bulk_insert_mappings(models.Cred, creds_batch)
    db.flush()
    log(f"  → {creds_n} creds inserted")

    log(f"Inserting {findings_n} findings")
    _seed_findings(db, PROJECT_ID, findings_n, host_ids)
    log(f"  → {findings_n} findings inserted")

    log(f"Inserting {scopes_n} scope entries")
    _seed_scopes(db, PROJECT_ID, scopes_n, host_ids)
    log(f"  → {scopes_n} scope entries inserted")

    # ── Loot ────────────────────────────────────────────────────────────────
    log(f"Inserting {loots_n} loot rows")
    loots_batch = []
    for i in range(loots_n):
        loots_batch.append({
            "id": f"lt_{PROJECT_ID}_{i:04d}",
            "pid": PROJECT_ID,
            "host_id": host_ids[random.randrange(hosts_n)] if random.random() > 0.3 else None,
            "loot_type": random.choice(["hash", "secret", "file", "config"]),
            "value": f"loot_value_{i}_content_here",
            "description": f"Auto-loot #{i}",
            "source_path": f"loot/loot_{i}.txt",
            "filename": "",
            "content_type": "",
            "file_size": 0,
            "storage_path": "",
            "public_url": "",
            "ts": _ts(),
            "job_id": "",
            "cred_id": "",
            "finding_id": "",
            "playbook_run_id": "",
            "sha256": "",
            "artifact_type": "file",
            "tags": [],
        })
    db.bulk_insert_mappings(models.Loot, loots_batch)
    db.flush()
    log(f"  → {loots_n} loot rows inserted")

    # ── HostActivities ──────────────────────────────────────────────────────
    log(f"Inserting {activities_n} host activities")
    activities_batch = []
    for i in range(activities_n):
        activities_batch.append({
            "id": f"ha_{PROJECT_ID}_{i:05d}",
            "pid": PROJECT_ID,
            "host_id": host_ids[random.randrange(hosts_n)],
            "title": f"Scan run #{i}",
            "activity_type": random.choice(ACTIVITY_TYPES),
            "command": f"nmap -sV -p- {random.choice(host_ips)}",
            "summary": "Discovered N open ports",
            "output": ("port " * 50)[: random.randint(100, 1000)],
            "status": random.choice(["done", "failed", "running"]),
            "ts": _ts(offset_minutes=random.randint(0, 60 * 24 * 7)),
            "job_id": "",
        })
    db.bulk_insert_mappings(models.HostActivity, activities_batch)
    db.flush()
    log(f"  → {activities_n} activities inserted")

    # ── Jobs ────────────────────────────────────────────────────────────────
    log(f"Inserting {jobs_n} jobs")
    _seed_jobs(db, PROJECT_ID, jobs_n, host_ips)
    log(f"  → {jobs_n} jobs inserted")

    # ── Timeline events ─────────────────────────────────────────────────────
    log(f"Inserting {timeline_n} timeline events")
    timeline_batch = []
    for i in range(timeline_n):
        timeline_batch.append({
            "id": f"evt_{PROJECT_ID}_{i:05d}",
            "pid": PROJECT_ID,
            "username": random.choice(["perfbench", "alice", "bob", "operator-3"]),
            "entity": random.choice(TIMELINE_ENTITIES),
            "action": random.choice(TIMELINE_ACTIONS),
            "label": f"Auto event #{i}",
            "meta": {},
            "ts": _ts(offset_minutes=random.randint(0, 60 * 24 * 7)),
        })
    db.bulk_insert_mappings(models.TimelineEvent, timeline_batch)
    db.flush()
    log(f"  → {timeline_n} timeline events inserted")

    # ── Network + Nodes + Edges ─────────────────────────────────────────────
    log(f"Creating network with {nodes_n} nodes + {edges_n} edges")
    _seed_network_data(db, PROJECT_ID, nodes_n, edges_n, host_ids, host_ips)
    log("  → network inserted")

    log("Committing...")
    db.commit()
    log(f"DONE in {time.time() - t0:.2f}s")


if __name__ == "__main__":
    db = SessionLocal()
    try:
        seed(db)
    finally:
        db.close()
