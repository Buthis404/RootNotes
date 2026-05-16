"""Built-in project templates with predefined checklists and notes."""
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models
from ..core.deps import get_current_user
from ..core.permissions import add_project_owner
from ..core.utils import new_id, ts_now, utcnow
from ..database import get_db

router = APIRouter(prefix="/api/project-templates", tags=["project-templates"])

TEMPLATES = {
    "web-app": {
        "id": "web-app",
        "name": "Web Application Pentest",
        "description": "OWASP-based web application penetration test template",
        "checklist": [
            ("Reconnaissance", "Passive recon: OSINT, subdomain enumeration"),
            ("Reconnaissance", "Active recon: port scan, service fingerprinting"),
            ("Reconnaissance", "Technology stack identification"),
            ("Enumeration", "Directory and endpoint brute-force"),
            ("Enumeration", "API endpoint discovery"),
            ("Enumeration", "Authentication mechanism analysis"),
            ("Exploitation", "OWASP Top 10: Injection (SQLi, XSS, XXE)"),
            ("Exploitation", "OWASP Top 10: Broken Authentication"),
            ("Exploitation", "OWASP Top 10: Sensitive Data Exposure"),
            ("Exploitation", "OWASP Top 10: IDOR / Broken Access Control"),
            ("Exploitation", "OWASP Top 10: Security Misconfiguration"),
            ("Exploitation", "OWASP Top 10: SSRF / RFI / LFI"),
            ("Post-Exploitation", "Session hijacking / token abuse"),
            ("Post-Exploitation", "Privilege escalation via application logic"),
            ("Reporting", "Screenshot and PoC collection"),
            ("Reporting", "Draft findings report"),
            ("Reporting", "Validate remediation recommendations"),
        ],
        "notes": [
            {
                "title": "Scope",
                "phase": "recon",
                "content": "## Scope\n\nList in-scope targets here.\n\n- Domains:\n- IPs:\n- Out of scope:\n",
            },
            {
                "title": "Credentials Found",
                "phase": "exploitation",
                "content": "## Credentials\n\nDocument discovered credentials here (use Creds tab for structured storage).\n",
            },
            {
                "title": "Report Draft",
                "phase": "reporting",
                "content": "## Executive Summary\n\n_High-level impact summary._\n\n## Findings\n\n_See Findings tab._\n\n## Recommendations\n\n",
            },
        ],
    },
    "internal-network": {
        "id": "internal-network",
        "name": "Internal Network Pentest",
        "description": "Kill-chain-based internal network penetration test",
        "checklist": [
            ("Reconnaissance", "Network discovery: ping sweep, ARP scan"),
            ("Reconnaissance", "Port and service scan (Nmap)"),
            ("Reconnaissance", "SMB enumeration (shares, users, policies)"),
            ("Reconnaissance", "SNMP enumeration"),
            ("Reconnaissance", "DNS zone transfer attempt"),
            ("Initial Access", "Credential spraying against identified services"),
            ("Initial Access", "Exploit unpatched services"),
            ("Initial Access", "Phishing simulation (if in scope)"),
            ("Lateral Movement", "Pass-the-Hash / Pass-the-Ticket"),
            ("Lateral Movement", "WMI / PSExec / SMB lateral movement"),
            ("Lateral Movement", "Kerberoasting"),
            ("Privilege Escalation", "Local privilege escalation"),
            ("Privilege Escalation", "Domain privilege escalation"),
            ("Post-Exploitation", "Credential dumping (LSASS, SAM, NTDS)"),
            ("Post-Exploitation", "Data exfiltration test"),
            ("Post-Exploitation", "Persistence mechanism (if in scope)"),
            ("Reporting", "Compile attack path narrative"),
            ("Reporting", "Map findings to MITRE ATT&CK"),
        ],
        "notes": [
            {
                "title": "Network Overview",
                "phase": "recon",
                "content": "## Network Segments\n\n| Subnet | Description | Key Hosts |\n|--------|-------------|----------|\n| | | |\n",
            },
            {
                "title": "Attack Path",
                "phase": "exploitation",
                "content": "## Attack Chain\n\n1. Initial access via: \n2. Lateral movement to: \n3. Domain compromise: \n",
            },
        ],
    },
    "active-directory": {
        "id": "active-directory",
        "name": "Active Directory Assessment",
        "description": "Comprehensive Active Directory security assessment",
        "checklist": [
            ("Enumeration", "Domain enumeration: users, groups, computers"),
            ("Enumeration", "BloodHound / SharpHound collection"),
            ("Enumeration", "GPO and ACL enumeration"),
            ("Enumeration", "Trust relationships mapping"),
            ("Enumeration", "Identify privileged accounts (DA, EA, Schema)"),
            ("Attack Paths", "AS-REP Roasting"),
            ("Attack Paths", "Kerberoasting (SPN accounts)"),
            ("Attack Paths", "Password spraying against AD"),
            ("Attack Paths", "ACL abuse (GenericAll, WriteDACL, etc.)"),
            ("Attack Paths", "DCSync attack path"),
            ("Attack Paths", "Silver / Golden ticket feasibility"),
            ("Attack Paths", "ADCS / Certificate abuse (ESC1-ESC8)"),
            ("Attack Paths", "LAPS review"),
            ("Attack Paths", "Unconstrained / constrained delegation"),
            ("Attack Paths", "PrintNightmare / other print spooler attacks"),
            ("Domain Compromise", "Domain Admin access achieved"),
            ("Domain Compromise", "NTDS.dit extraction"),
            ("Reporting", "BloodHound attack path export"),
            ("Reporting", "Tiering model assessment"),
        ],
        "notes": [
            {
                "title": "Domain Info",
                "phase": "recon",
                "content": "## Domain Details\n\n- Domain name: \n- Forest: \n- Domain Controllers: \n- Functional level: \n",
            },
            {
                "title": "Privileged Accounts",
                "phase": "exploitation",
                "content": "## Privileged Accounts\n\n| Account | Group | Notes |\n|---------|-------|-------|\n| | | |\n",
            },
            {
                "title": "BloodHound Findings",
                "phase": "exploitation",
                "content": "## BloodHound Attack Paths\n\nDocument key attack paths discovered here.\n",
            },
        ],
    },
    "ctf": {
        "id": "ctf",
        "name": "CTF / Challenge",
        "description": "Capture the Flag event tracking",
        "checklist": [
            ("Web", "SQL Injection"),
            ("Web", "XSS / CSRF"),
            ("Web", "File upload bypass"),
            ("Web", "IDOR / Auth bypass"),
            ("Web", "SSTI / SSRF"),
            ("Crypto", "Classical ciphers"),
            ("Crypto", "RSA / asymmetric"),
            ("Crypto", "Hash cracking"),
            ("Binary", "Buffer overflow"),
            ("Binary", "Format string"),
            ("Binary", "ROP chain"),
            ("Reversing", "Static analysis"),
            ("Reversing", "Dynamic analysis / debugging"),
            ("Forensics", "Steganography"),
            ("Forensics", "Memory forensics"),
            ("Forensics", "PCAP analysis"),
            ("Misc", "OSINT"),
            ("Misc", "Pwn"),
        ],
        "notes": [
            {
                "title": "Flag Log",
                "phase": "exploitation",
                "content": "## Captured Flags\n\n| Challenge | Flag | Points | Notes |\n|-----------|------|--------|-------|\n| | | | |\n",
            },
        ],
    },
}


@router.get("")
def list_templates():
    return [
        {"id": t["id"], "name": t["name"], "description": t["description"]}
        for t in TEMPLATES.values()
    ]


@router.post("/{template_id}/apply", status_code=201)
def apply_template(
    template_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    tpl = TEMPLATES.get(template_id)
    if not tpl:
        raise HTTPException(404, "Template not found")

    ts = ts_now()
    now = utcnow()

    # Create project
    project = models.Project(
        id=new_id("p"),
        name=tpl["name"],
        status="active",
        ip="",
        os="",
        added=ts,
        description=tpl["description"],
    )
    db.add(project)
    db.flush()

    # Make current user owner
    add_project_owner(db, project.id, user.id, created_by=user.id)

    # Create checklist items
    for idx, (phase, text) in enumerate(tpl.get("checklist", [])):
        db.add(models.ChecklistItem(
            id=new_id("ci"),
            pid=project.id,
            phase=phase,
            text=text,
            done=False,
            order_idx=idx,
        ))

    # Create starter notes
    for note_data in tpl.get("notes", []):
        db.add(models.Note(
            id=new_id("n"),
            pid=project.id,
            title=note_data["title"],
            phase=note_data.get("phase", "recon"),
            tags=[],
            content=note_data.get("content", ""),
            ts=ts,
            starred=False,
            version=0,
        ))

    db.commit()
    db.refresh(project)
    return {
        "id": project.id,
        "name": project.name,
        "status": project.status,
        "added": project.added,
        "description": project.description,
    }
