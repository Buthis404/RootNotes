"""
Knowledge Base router.

GET    /api/kb?pid=&category=&q=   list articles
POST   /api/kb                     create article
GET    /api/kb/{aid}               get single article
PATCH  /api/kb/{aid}               update article
DELETE /api/kb/{aid}               delete article (204)
"""
import io
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models, schemas
from ..core.access import check_pid_access, get_user_member_pids
from ..core.deps import get_current_user, require_admin, is_admin
from ..core.utils import new_id, ts_now

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/kb", tags=["kb"])

MITRE_CATEGORY = "MITRE ATT&CK"

# fmt: off
_MITRE_SEED = [
    ("T1595",     "Reconnaissance",        "Active Scanning",             "Adversaries scan for IP ranges, open ports, and services to identify potential targets."),
    ("T1590",     "Reconnaissance",        "Gather Victim Network Info",  "Adversaries gather network topology, IP ranges, domain/DNS info, and infrastructure data."),
    ("T1589",     "Reconnaissance",        "Gather Victim Identity Info", "Adversaries collect email addresses, employee names, and credentials from public sources."),
    ("T1566",     "Initial Access",        "Phishing",                    "Adversaries send malicious links or attachments via email to gain initial access."),
    ("T1190",     "Initial Access",        "Exploit Public-Facing App",   "Exploit vulnerabilities in public-facing web applications, VPNs, or services."),
    ("T1133",     "Initial Access",        "External Remote Services",    "Exploit externally facing remote services such as VPN, RDP, or Citrix."),
    ("T1078",     "Initial Access",        "Valid Accounts",              "Use legitimate credentials (default, stolen, or compromised) to authenticate to services."),
    ("T1091",     "Initial Access",        "Removable Media",             "Use infected removable media (USB) to introduce malware into air-gapped or restricted networks."),
    ("T1059",     "Execution",             "Command Interpreter",         "Abuse command-line interpreters (cmd, bash, PowerShell) to execute commands."),
    ("T1059.001", "Execution",             "PowerShell",                  "Execute commands and scripts using PowerShell. Supports encoded commands, remoting, and AMSI bypass."),
    ("T1059.003", "Execution",             "Windows CMD Shell",           "Execute commands via cmd.exe. Often used in batch scripts or as a fallback interpreter."),
    ("T1047",     "Execution",             "WMI",                         "Use Windows Management Instrumentation to execute code, query system info, or move laterally."),
    ("T1053",     "Execution",             "Scheduled Task",              "Create or abuse scheduled tasks/cron jobs for code execution or persistence."),
    ("T1136",     "Persistence",           "Create Account",              "Create local or domain accounts for persistent access."),
    ("T1547",     "Persistence",           "Boot Autostart Execution",    "Modify autostart locations (registry run keys, startup folder) to persist across reboots."),
    ("T1505.003", "Persistence",           "Web Shell",                   "Upload a web shell to a compromised web server for persistent remote command execution."),
    ("T1548",     "Privilege Escalation",  "Abuse Elevation Control",     "Exploit UAC bypass techniques or setuid/setgid binaries to elevate privileges."),
    ("T1134",     "Privilege Escalation",  "Access Token Manipulation",   "Manipulate Windows access tokens to escalate privileges or impersonate users."),
    ("T1068",     "Privilege Escalation",  "Exploit for Priv Escalation", "Exploit software vulnerabilities in the OS or local applications to gain elevated privileges."),
    ("T1484",     "Privilege Escalation",  "Domain Policy Modification",  "Modify Group Policy Objects (GPOs) or domain trust settings to escalate within the domain."),
    ("T1070",     "Defense Evasion",       "Indicator Removal",           "Clear logs, modify timestamps, or delete artifacts to remove evidence of compromise."),
    ("T1036",     "Defense Evasion",       "Masquerading",                "Rename binaries or disguise malicious content to look like legitimate files."),
    ("T1027",     "Defense Evasion",       "Obfuscated Files",            "Obfuscate payloads using encoding, encryption, or packing to evade detection."),
    ("T1055",     "Defense Evasion",       "Process Injection",           "Inject code into legitimate processes (DLL injection, shellcode, reflective loading)."),
    ("T1562",     "Defense Evasion",       "Impair Defenses",             "Disable AV, EDR, firewalls, or audit logging to reduce detection capability."),
    ("T1003",     "Credential Access",     "OS Credential Dumping",       "Dump credentials from OS memory or storage (LSASS, SAM, NTDS)."),
    ("T1003.001", "Credential Access",     "LSASS Memory",                "Dump NTLM hashes and Kerberos tickets from LSASS memory using tools like Mimikatz or ProcDump."),
    ("T1003.003", "Credential Access",     "NTDS",                        "Extract password hashes from the Active Directory database (ntds.dit) using VSS or DCSync."),
    ("T1558",     "Credential Access",     "Steal Kerberos Tickets",      "Steal or forge Kerberos tickets to authenticate as other users."),
    ("T1558.003", "Credential Access",     "Kerberoasting",               "Request TGS tickets for SPNs and crack them offline to recover service account passwords."),
    ("T1558.004", "Credential Access",     "AS-REP Roasting",             "Exploit accounts with Kerberos pre-auth disabled to crack their password offline."),
    ("T1110",     "Credential Access",     "Brute Force",                 "Attempt multiple passwords against one or more accounts to guess valid credentials."),
    ("T1110.003", "Credential Access",     "Password Spraying",           "Try a small set of common passwords against many accounts to avoid lockouts."),
    ("T1212",     "Credential Access",     "Exploit for Credentials",     "Exploit software vulnerabilities to extract credentials from memory or storage."),
    ("T1046",     "Discovery",             "Network Service Scanning",    "Scan for open ports and running services to identify targets and attack surface."),
    ("T1049",     "Discovery",             "Network Connections Discovery","Enumerate active network connections and listening ports on compromised hosts."),
    ("T1069",     "Discovery",             "Permission Groups Discovery", "Enumerate local and domain groups to identify privileged memberships."),
    ("T1069.002", "Discovery",             "Domain Groups",               "Enumerate Active Directory groups, especially privileged ones like Domain Admins."),
    ("T1082",     "Discovery",             "System Info Discovery",       "Gather OS version, architecture, hostname, and installed software information."),
    ("T1087",     "Discovery",             "Account Discovery",           "Enumerate local and domain user accounts."),
    ("T1087.002", "Discovery",             "Domain Account Discovery",    "Enumerate Active Directory user accounts using LDAP, net commands, or BloodHound."),
    ("T1021",     "Lateral Movement",      "Remote Services",             "Use legitimate remote services (SSH, RDP, WinRM, SMB) to move between hosts."),
    ("T1021.001", "Lateral Movement",      "RDP",                         "Use Remote Desktop Protocol with valid credentials to access other systems."),
    ("T1021.002", "Lateral Movement",      "SMB / Admin Shares",          "Use SMB admin shares (C$, ADMIN$, IPC$) with valid credentials for lateral movement."),
    ("T1021.004", "Lateral Movement",      "SSH",                         "Use SSH with valid credentials or keys to connect to remote Linux/Unix hosts."),
    ("T1021.006", "Lateral Movement",      "WinRM",                       "Use Windows Remote Management (WinRM/WSMan) to execute commands on remote Windows hosts."),
    ("T1550",     "Lateral Movement",      "Alternate Auth Material",     "Use alternative authentication material (hashes, tickets, keys) instead of plaintext passwords."),
    ("T1550.002", "Lateral Movement",      "Pass the Hash",               "Authenticate using an NTLM hash without knowing the plaintext password."),
    ("T1550.003", "Lateral Movement",      "Pass the Ticket",             "Inject a Kerberos ticket into the current session to authenticate as another user."),
    ("T1570",     "Lateral Movement",      "Lateral Tool Transfer",       "Transfer tools or payloads to compromised hosts via SMB, SCP, or other file transfer methods."),
    ("T1005",     "Collection",            "Data from Local System",      "Collect files and data of interest from the local file system."),
    ("T1039",     "Collection",            "Data from Network Share",     "Collect data from network shares accessible from compromised hosts."),
    ("T1560",     "Collection",            "Archive Collected Data",      "Archive collected files using zip, tar, or encryption before exfiltration."),
    ("T1071",     "Command and Control",   "Application Layer Protocol",  "Use application-layer protocols (HTTP/S, DNS, SMTP) for C2 communication to blend with normal traffic."),
    ("T1090",     "Command and Control",   "Proxy",                       "Use proxies to route C2 traffic and obscure the adversary's infrastructure."),
    ("T1090.001", "Command and Control",   "Internal Proxy / Pivot",      "Use compromised hosts as internal proxies/SOCKS listeners to pivot deeper into the network."),
    ("T1095",     "Command and Control",   "Non-App Layer Protocol",      "Use raw TCP/UDP or ICMP for C2 to avoid application-layer filtering."),
    ("T1572",     "Command and Control",   "Protocol Tunneling",          "Tunnel C2 or tool traffic inside legitimate protocols (DNS, ICMP, HTTP) or tools like chisel/ligolo."),
    ("T1041",     "Exfiltration",          "Exfil Over C2 Channel",       "Exfiltrate data over the existing C2 channel to minimize network footprint."),
    ("T1048",     "Exfiltration",          "Exfil Over Alt Protocol",     "Use alternative protocols (DNS, ICMP, SMTP) to exfiltrate data outside normal C2 paths."),
    ("T1486",     "Impact",               "Data Encrypted for Impact",   "Encrypt data on target systems to interrupt availability (ransomware simulation)."),
    ("T1531",     "Impact",               "Account Access Removal",      "Delete, disable, or lock accounts to deny access to defenders or demonstrate impact."),
]
# fmt: on


def _now() -> str:
    return ts_now()


def _can_write_global(user: models.User) -> bool:
    """Global (pid=None) KB articles are admin-only for write."""
    return is_admin(user)


@router.get("", response_model=list[schemas.KBArticle])
def list_kb_articles(
    pid: Optional[str] = None,
    category: Optional[str] = None,
    q: Optional[str] = None,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    if pid:
        check_pid_access(db, pid, user, "kb.read")
        # Return global (pid IS NULL) + project articles
        query = db.query(models.KBArticle).filter(
            (models.KBArticle.pid == None) | (models.KBArticle.pid == pid)
        )
    else:
        # Return only global articles — readable by any authenticated user
        query = db.query(models.KBArticle).filter(models.KBArticle.pid == None)

    if category:
        query = query.filter(models.KBArticle.category == category)

    articles = query.all()

    if q:
        q_lower = q.lower()
        articles = [
            a for a in articles
            if q_lower in a.title.lower() or q_lower in (a.content or "").lower()
        ]

    return articles


@router.post("", response_model=schemas.KBArticle, status_code=201)
def create_kb_article(
    body: schemas.KBArticleCreate,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    if body.pid:
        check_pid_access(db, body.pid, user, "kb.create")
    elif not _can_write_global(user):
        raise HTTPException(403, "Global KB articles can only be created by global admins")

    now = _now()
    article = models.KBArticle(
        id=new_id("kb"),
        pid=body.pid,
        title=body.title,
        content=body.content,
        category=body.category,
        tags=body.tags or [],
        created_by=user.username,
        created_at=now,
        updated_at=now,
    )
    db.add(article)
    db.commit()
    db.refresh(article)
    return article


# ── KB export / import ────────────────────────────────────────────────────────

@router.get("/export")
def export_kb(
    pid: Optional[str] = None,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    if pid:
        check_pid_access(db, pid, user, "kb.export")
    elif not is_admin(user):
        raise HTTPException(403, "Global KB export requires global admin")
    q = db.query(models.KBArticle)
    if pid:
        q = q.filter((models.KBArticle.pid == pid) | (models.KBArticle.pid == None))
    articles = q.order_by(models.KBArticle.category, models.KBArticle.title).all()
    data = [
        {
            "title": a.title, "content": a.content,
            "category": a.category, "tags": a.tags or [],
            "pid": a.pid,
        }
        for a in articles
        if a.category != MITRE_CATEGORY  # skip auto-seeded MITRE — re-seed via /kb/seed/mitre
    ]
    payload = json.dumps({"format": "rootnotes-kb", "version": "1", "articles": data}, ensure_ascii=False, indent=2).encode()
    return StreamingResponse(io.BytesIO(payload), media_type="application/json",
                             headers={"Content-Disposition": 'attachment; filename="kb_articles.json"'})


@router.post("/import", status_code=201)
async def import_kb(
    file: UploadFile = File(...),
    pid: Optional[str] = None,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    if pid:
        check_pid_access(db, pid, user, "kb.create")
    elif not is_admin(user):
        raise HTTPException(403, "Global KB import requires global admin")
    raw = json.loads((await file.read()).decode())
    articles = raw if isinstance(raw, list) else raw.get("articles", [])
    now = ts_now()
    created = skipped = 0
    for item in articles:
        title = (item.get("title") or "").strip()
        category = (item.get("category") or "General").strip()
        if not title or category == MITRE_CATEGORY:
            skipped += 1
            continue
        target_pid = pid or item.get("pid")
        if target_pid and target_pid != pid and not is_admin(user):
            # Item carried a foreign pid the importer doesn't own
            if not any(target_pid == m for m in get_user_member_pids(db, user)):
                skipped += 1
                continue
        existing = db.query(models.KBArticle).filter(
            models.KBArticle.title == title,
            models.KBArticle.category == category,
            models.KBArticle.pid == target_pid,
        ).first()
        if existing:
            skipped += 1
            continue
        db.add(models.KBArticle(
            id=new_id("kb"),
            pid=target_pid,
            title=title,
            content=item.get("content", ""),
            category=category,
            tags=item.get("tags", []),
            created_by=user.username,
            created_at=now,
            updated_at=now,
        ))
        created += 1
    db.commit()
    return {"created": created, "skipped": skipped}


@router.get("/{aid}", response_model=schemas.KBArticle)
def get_kb_article(
    aid: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    article = db.query(models.KBArticle).filter(models.KBArticle.id == aid).first()
    if not article:
        raise HTTPException(404, "Article not found")
    if article.pid:
        check_pid_access(db, article.pid, user, "kb.read")
    return article


@router.patch("/{aid}", response_model=schemas.KBArticle)
def update_kb_article(
    aid: str,
    body: schemas.KBArticleUpdate,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    article = db.query(models.KBArticle).filter(models.KBArticle.id == aid).first()
    if not article:
        raise HTTPException(404, "Article not found")
    if article.pid:
        check_pid_access(db, article.pid, user, "kb.update")
    elif not _can_write_global(user):
        raise HTTPException(403, "Global KB articles can only be edited by global admins")

    for k, v in body.model_dump(exclude_none=True).items():
        setattr(article, k, v)
    article.updated_at = _now()

    db.commit()
    db.refresh(article)
    return article


@router.delete("/{aid}", status_code=204)
def delete_kb_article(
    aid: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    article = db.query(models.KBArticle).filter(models.KBArticle.id == aid).first()
    if not article:
        raise HTTPException(404, "Article not found")
    if article.pid:
        check_pid_access(db, article.pid, user, "kb.delete")
    elif not _can_write_global(user):
        raise HTTPException(403, "Global KB articles can only be deleted by global admins")
    db.delete(article)
    db.commit()


@router.post("/seed/mitre", status_code=200)
def seed_mitre(
    db: Session = Depends(get_db),
    _: models.User = Depends(require_admin),
):
    """Seed global KB with MITRE ATT&CK technique articles (idempotent)."""
    existing_ids = {
        a.tags[0]
        for a in db.query(models.KBArticle).filter(
            models.KBArticle.pid == None,
            models.KBArticle.category == MITRE_CATEGORY,
        ).all()
        if a.tags
    }

    now = _now()
    created = 0
    for mid, tactic, name, description in _MITRE_SEED:
        if mid in existing_ids:
            continue
        content = f"## {name}\n\n**Tactic:** {tactic}  \n**ID:** [{mid}](https://attack.mitre.org/techniques/{mid.replace('.', '/')})\n\n{description}\n"
        article = models.KBArticle(
            id=new_id("kb"),
            pid=None,
            title=f"{mid} — {name}",
            content=content,
            category=MITRE_CATEGORY,
            tags=[mid, tactic.lower().replace(" ", "_"), "mitre"],
            created_by=user.username,
            created_at=now,
            updated_at=now,
        )
        db.add(article)
        created += 1

    db.commit()
    return {"created": created, "skipped": len(_MITRE_SEED) - created, "total": len(_MITRE_SEED)}
