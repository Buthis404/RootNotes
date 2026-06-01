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

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from typing import Annotated
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.access import check_pid_access, get_user_member_pids
from ..core.deps import get_current_user, is_admin, require_admin
from ..core.utils import new_id, ts_now
from ..database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/kb", tags=["kb"],
    responses={
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)

MITRE_CATEGORY = "MITRE ATT&CK"
_CAT_INITIAL_ACCESS = "Initial Access"
_CAT_PRIVILEGE_ESCALATION = "Privilege Escalation"
_CAT_DEFENSE_EVASION = "Defense Evasion"
_CAT_CREDENTIAL_ACCESS = "Credential Access"
_CAT_LATERAL_MOVEMENT = "Lateral Movement"
_CAT_COMMAND_AND_CONTROL = "Command and Control"
_MSG_ARTICLE_NOT_FOUND = "Article not found"

# fmt: off
_MITRE_SEED = [
    ("T1595",     "Reconnaissance",        "Active Scanning",             "Adversaries scan for IP ranges, open ports, and services to identify potential targets."),
    ("T1590",     "Reconnaissance",        "Gather Victim Network Info",  "Adversaries gather network topology, IP ranges, domain/DNS info, and infrastructure data."),
    ("T1589",     "Reconnaissance",        "Gather Victim Identity Info", "Adversaries collect email addresses, employee names, and credentials from public sources."),
    ("T1566",     _CAT_INITIAL_ACCESS,        "Phishing",                    "Adversaries send malicious links or attachments via email to gain initial access."),
    ("T1190",     _CAT_INITIAL_ACCESS,        "Exploit Public-Facing App",   "Exploit vulnerabilities in public-facing web applications, VPNs, or services."),
    ("T1133",     _CAT_INITIAL_ACCESS,        "External Remote Services",    "Exploit externally facing remote services such as VPN, RDP, or Citrix."),
    ("T1078",     _CAT_INITIAL_ACCESS,        "Valid Accounts",              "Use legitimate credentials (default, stolen, or compromised) to authenticate to services."),
    ("T1091",     _CAT_INITIAL_ACCESS,        "Removable Media",             "Use infected removable media (USB) to introduce malware into air-gapped or restricted networks."),
    ("T1059",     "Execution",             "Command Interpreter",         "Abuse command-line interpreters (cmd, bash, PowerShell) to execute commands."),
    ("T1059.001", "Execution",             "PowerShell",                  "Execute commands and scripts using PowerShell. Supports encoded commands, remoting, and AMSI bypass."),
    ("T1059.003", "Execution",             "Windows CMD Shell",           "Execute commands via cmd.exe. Often used in batch scripts or as a fallback interpreter."),
    ("T1047",     "Execution",             "WMI",                         "Use Windows Management Instrumentation to execute code, query system info, or move laterally."),
    ("T1053",     "Execution",             "Scheduled Task",              "Create or abuse scheduled tasks/cron jobs for code execution or persistence."),
    ("T1136",     "Persistence",           "Create Account",              "Create local or domain accounts for persistent access."),
    ("T1547",     "Persistence",           "Boot Autostart Execution",    "Modify autostart locations (registry run keys, startup folder) to persist across reboots."),
    ("T1505.003", "Persistence",           "Web Shell",                   "Upload a web shell to a compromised web server for persistent remote command execution."),
    ("T1548",     _CAT_PRIVILEGE_ESCALATION,  "Abuse Elevation Control",     "Exploit UAC bypass techniques or setuid/setgid binaries to elevate privileges."),
    ("T1134",     _CAT_PRIVILEGE_ESCALATION,  "Access Token Manipulation",   "Manipulate Windows access tokens to escalate privileges or impersonate users."),
    ("T1068",     _CAT_PRIVILEGE_ESCALATION,  "Exploit for Priv Escalation", "Exploit software vulnerabilities in the OS or local applications to gain elevated privileges."),
    ("T1484",     _CAT_PRIVILEGE_ESCALATION,  "Domain Policy Modification",  "Modify Group Policy Objects (GPOs) or domain trust settings to escalate within the domain."),
    ("T1070",     _CAT_DEFENSE_EVASION,       "Indicator Removal",           "Clear logs, modify timestamps, or delete artifacts to remove evidence of compromise."),
    ("T1036",     _CAT_DEFENSE_EVASION,       "Masquerading",                "Rename binaries or disguise malicious content to look like legitimate files."),
    ("T1027",     _CAT_DEFENSE_EVASION,       "Obfuscated Files",            "Obfuscate payloads using encoding, encryption, or packing to evade detection."),
    ("T1055",     _CAT_DEFENSE_EVASION,       "Process Injection",           "Inject code into legitimate processes (DLL injection, shellcode, reflective loading)."),
    ("T1562",     _CAT_DEFENSE_EVASION,       "Impair Defenses",             "Disable AV, EDR, firewalls, or audit logging to reduce detection capability."),
    ("T1003",     _CAT_CREDENTIAL_ACCESS,     "OS Credential Dumping",       "Dump credentials from OS memory or storage (LSASS, SAM, NTDS)."),
    ("T1003.001", _CAT_CREDENTIAL_ACCESS,     "LSASS Memory",                "Dump NTLM hashes and Kerberos tickets from LSASS memory using tools like Mimikatz or ProcDump."),
    ("T1003.003", _CAT_CREDENTIAL_ACCESS,     "NTDS",                        "Extract password hashes from the Active Directory database (ntds.dit) using VSS or DCSync."),
    ("T1558",     _CAT_CREDENTIAL_ACCESS,     "Steal Kerberos Tickets",      "Steal or forge Kerberos tickets to authenticate as other users."),
    ("T1558.003", _CAT_CREDENTIAL_ACCESS,     "Kerberoasting",               "Request TGS tickets for SPNs and crack them offline to recover service account passwords."),
    ("T1558.004", _CAT_CREDENTIAL_ACCESS,     "AS-REP Roasting",             "Exploit accounts with Kerberos pre-auth disabled to crack their password offline."),
    ("T1110",     _CAT_CREDENTIAL_ACCESS,     "Brute Force",                 "Attempt multiple passwords against one or more accounts to guess valid credentials."),
    ("T1110.003", _CAT_CREDENTIAL_ACCESS,     "Password Spraying",           "Try a small set of common passwords against many accounts to avoid lockouts."),
    ("T1212",     _CAT_CREDENTIAL_ACCESS,     "Exploit for Credentials",     "Exploit software vulnerabilities to extract credentials from memory or storage."),
    ("T1046",     "Discovery",             "Network Service Scanning",    "Scan for open ports and running services to identify targets and attack surface."),
    ("T1049",     "Discovery",             "Network Connections Discovery","Enumerate active network connections and listening ports on compromised hosts."),
    ("T1069",     "Discovery",             "Permission Groups Discovery", "Enumerate local and domain groups to identify privileged memberships."),
    ("T1069.002", "Discovery",             "Domain Groups",               "Enumerate Active Directory groups, especially privileged ones like Domain Admins."),
    ("T1082",     "Discovery",             "System Info Discovery",       "Gather OS version, architecture, hostname, and installed software information."),
    ("T1087",     "Discovery",             "Account Discovery",           "Enumerate local and domain user accounts."),
    ("T1087.002", "Discovery",             "Domain Account Discovery",    "Enumerate Active Directory user accounts using LDAP, net commands, or BloodHound."),
    ("T1021",     _CAT_LATERAL_MOVEMENT,      "Remote Services",             "Use legitimate remote services (SSH, RDP, WinRM, SMB) to move between hosts."),
    ("T1021.001", _CAT_LATERAL_MOVEMENT,      "RDP",                         "Use Remote Desktop Protocol with valid credentials to access other systems."),
    ("T1021.002", _CAT_LATERAL_MOVEMENT,      "SMB / Admin Shares",          "Use SMB admin shares (C$, ADMIN$, IPC$) with valid credentials for lateral movement."),
    ("T1021.004", _CAT_LATERAL_MOVEMENT,      "SSH",                         "Use SSH with valid credentials or keys to connect to remote Linux/Unix hosts."),
    ("T1021.006", _CAT_LATERAL_MOVEMENT,      "WinRM",                       "Use Windows Remote Management (WinRM/WSMan) to execute commands on remote Windows hosts."),
    ("T1550",     _CAT_LATERAL_MOVEMENT,      "Alternate Auth Material",     "Use alternative authentication material (hashes, tickets, keys) instead of plaintext passwords."),
    ("T1550.002", _CAT_LATERAL_MOVEMENT,      "Pass the Hash",               "Authenticate using an NTLM hash without knowing the plaintext password."),
    ("T1550.003", _CAT_LATERAL_MOVEMENT,      "Pass the Ticket",             "Inject a Kerberos ticket into the current session to authenticate as another user."),
    ("T1570",     _CAT_LATERAL_MOVEMENT,      "Lateral Tool Transfer",       "Transfer tools or payloads to compromised hosts via SMB, SCP, or other file transfer methods."),
    ("T1005",     "Collection",            "Data from Local System",      "Collect files and data of interest from the local file system."),
    ("T1039",     "Collection",            "Data from Network Share",     "Collect data from network shares accessible from compromised hosts."),
    ("T1560",     "Collection",            "Archive Collected Data",      "Archive collected files using zip, tar, or encryption before exfiltration."),
    ("T1071",     _CAT_COMMAND_AND_CONTROL,   "Application Layer Protocol",  "Use application-layer protocols (HTTP/S, DNS, SMTP) for C2 communication to blend with normal traffic."),
    ("T1090",     _CAT_COMMAND_AND_CONTROL,   "Proxy",                       "Use proxies to route C2 traffic and obscure the adversary's infrastructure."),
    ("T1090.001", _CAT_COMMAND_AND_CONTROL,   "Internal Proxy / Pivot",      "Use compromised hosts as internal proxies/SOCKS listeners to pivot deeper into the network."),
    ("T1095",     _CAT_COMMAND_AND_CONTROL,   "Non-App Layer Protocol",      "Use raw TCP/UDP or ICMP for C2 to avoid application-layer filtering."),
    ("T1572",     _CAT_COMMAND_AND_CONTROL,   "Protocol Tunneling",          "Tunnel C2 or tool traffic inside legitimate protocols (DNS, ICMP, HTTP) or tools like chisel/ligolo."),
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
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    pid: str | None = None,
    category: str | None = None,
    q: str | None = None,
):
    if pid:
        check_pid_access(db, pid, user, "kb.read")
        # Return global (pid IS NULL) + project articles
        query = db.query(models.KBArticle).filter(
            (models.KBArticle.pid == None) | (models.KBArticle.pid == pid)  # noqa: E711
        )
    else:
        # Return only global articles — readable by any authenticated user
        query = db.query(models.KBArticle).filter(models.KBArticle.pid == None)  # noqa: E711

    if category:
        query = query.filter(models.KBArticle.category == category)

    articles = query.all()

    if q:
        q_lower = q.lower()
        articles = [
            a
            for a in articles
            if q_lower in a.title.lower() or q_lower in (a.content or "").lower()
        ]

    return articles


@router.post("", response_model=schemas.KBArticle, status_code=201, responses={403: {"description": "Forbidden"}})
def create_kb_article(
    body: schemas.KBArticleCreate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
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


@router.get("/export", responses={403: {"description": "Forbidden"}})
def export_kb(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    pid: str | None = None,
):
    if pid:
        check_pid_access(db, pid, user, "kb.export")
    elif not is_admin(user):
        raise HTTPException(403, "Global KB export requires global admin")
    q = db.query(models.KBArticle)
    if pid:
        q = q.filter((models.KBArticle.pid == pid) | (models.KBArticle.pid == None))  # noqa: E711
    articles = q.order_by(models.KBArticle.category, models.KBArticle.title).all()
    data = [
        {
            "title": a.title,
            "content": a.content,
            "category": a.category,
            "tags": a.tags or [],
            "pid": a.pid,
        }
        for a in articles
        if a.category != MITRE_CATEGORY  # skip auto-seeded MITRE — re-seed via /kb/seed/mitre
    ]
    payload = json.dumps(
        {"format": "rootnotes-kb", "version": "1", "articles": data}, ensure_ascii=False, indent=2
    ).encode()
    return StreamingResponse(
        io.BytesIO(payload),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="kb_articles.json"'},
    )


def _import_kb_item(db, item: dict, pid: str | None, user, now: str) -> bool:
    """Try to import one KB item. Returns True if created, False if skipped."""
    title = (item.get("title") or "").strip()
    category = (item.get("category") or "General").strip()
    if not title or category == MITRE_CATEGORY:
        return False
    target_pid = pid or item.get("pid")
    if target_pid and target_pid != pid and not is_admin(user):
        if not any(target_pid == m for m in get_user_member_pids(db, user)):
            return False
    existing = (
        db.query(models.KBArticle)
        .filter(
            models.KBArticle.title == title,
            models.KBArticle.category == category,
            models.KBArticle.pid == target_pid,
        )
        .first()
    )
    if existing:
        return False
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
    return True


@router.post("/import", status_code=201, responses={403: {"description": "Forbidden"}})
async def import_kb(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    file: Annotated[UploadFile, File()],
    pid: str | None = None,
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
        if _import_kb_item(db, item, pid, user, now):
            created += 1
        else:
            skipped += 1
    db.commit()
    return {"created": created, "skipped": skipped}


@router.get("/{aid}", response_model=schemas.KBArticle, responses={404: {"description": "Not found"}})
def get_kb_article(
    aid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    article = db.query(models.KBArticle).filter(models.KBArticle.id == aid).first()
    if not article:
        raise HTTPException(404, _MSG_ARTICLE_NOT_FOUND)
    if article.pid:
        check_pid_access(db, article.pid, user, "kb.read")
    return article


@router.patch("/{aid}", response_model=schemas.KBArticle, responses={403: {"description": "Forbidden"}, 404: {"description": "Not found"}})
def update_kb_article(
    aid: str,
    body: schemas.KBArticleUpdate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    article = db.query(models.KBArticle).filter(models.KBArticle.id == aid).first()
    if not article:
        raise HTTPException(404, _MSG_ARTICLE_NOT_FOUND)
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


@router.delete("/{aid}", status_code=204, responses={403: {"description": "Forbidden"}, 404: {"description": "Not found"}})
def delete_kb_article(
    aid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    article = db.query(models.KBArticle).filter(models.KBArticle.id == aid).first()
    if not article:
        raise HTTPException(404, _MSG_ARTICLE_NOT_FOUND)
    if article.pid:
        check_pid_access(db, article.pid, user, "kb.delete")
    elif not _can_write_global(user):
        raise HTTPException(403, "Global KB articles can only be deleted by global admins")
    db.delete(article)
    db.commit()


@router.post("/seed/mitre", status_code=200)
def seed_mitre(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(require_admin)],
):
    """Seed global KB with MITRE ATT&CK technique articles (idempotent)."""
    existing_ids = {
        a.tags[0]
        for a in db.query(models.KBArticle)
        .filter(
            models.KBArticle.pid == None,  # noqa: E711
            models.KBArticle.category == MITRE_CATEGORY,
        )
        .all()
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
