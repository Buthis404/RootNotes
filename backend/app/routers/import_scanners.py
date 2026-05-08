"""
Scanner import endpoints.

POST /api/projects/{pid}/import/nessus  — import .nessus XML file
POST /api/projects/{pid}/import/burp    — import Burp Suite XML file
"""
import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models
from ..core.deps import get_current_user
from ..core.access import check_pid_access
from ..core.utils import new_id
from ..core.events import log_event

logger = logging.getLogger(__name__)

router = APIRouter(tags=["import_scanners"])


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _strip_html(text: str) -> str:
    """Remove HTML tags from text."""
    if not text:
        return ""
    return re.sub(r"<[^>]+>", "", text).strip()


_NESSUS_SEVERITY_MAP = {
    "4": "critical",
    "3": "high",
    "2": "medium",
    "1": "low",
    "0": "info",
}

_BURP_SEVERITY_MAP = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "information": "info",
    "informational": "info",
    "info": "info",
    "critical": "critical",
}


# ── Nessus ────────────────────────────────────────────────────────────

def _parse_nessus(db: Session, pid: str, content: bytes) -> dict:
    hosts_created = 0
    hosts_updated = 0
    findings_created = 0
    findings_skipped = 0

    try:
        root = ET.fromstring(content)
    except ET.ParseError as e:
        raise HTTPException(400, f"Invalid XML: {e}")

    for report_host in root.iter("ReportHost"):
        ip = report_host.attrib.get("name", "")
        hostname = ""
        os_str = ""

        for tag in report_host.iter("tag"):
            tag_name = tag.attrib.get("name", "")
            tag_value = (tag.text or "").strip()
            if tag_name == "host-ip":
                ip = tag_value or ip
            elif tag_name == "host-fqdn":
                hostname = tag_value
            elif tag_name == "operating-system":
                os_str = tag_value
            elif tag_name == "host-rdns" and not hostname:
                hostname = tag_value

        if not ip:
            continue

        # Find or create host
        host = db.query(models.Host).filter(
            models.Host.pid == pid, models.Host.ip == ip
        ).first()
        if host:
            if hostname and not host.hostname:
                host.hostname = hostname
            if os_str and not host.os:
                host.os = os_str
            hosts_updated += 1
        else:
            host = models.Host(
                id=new_id("h"),
                pid=pid,
                ip=ip,
                hostname=hostname or "",
                os=os_str or "Unknown",
                status="unknown",
                ports=[],
                services=[],
                tags=[],
                notes="",
                domain="",
                role="unknown",
                is_attacker=False,
                import_source="nessus",
            )
            db.add(host)
            db.flush()
            hosts_created += 1

        # Process findings
        for item in report_host.iter("ReportItem"):
            severity_num = item.attrib.get("severity", "0")
            if severity_num == "0":
                findings_skipped += 1
                continue

            severity = _NESSUS_SEVERITY_MAP.get(severity_num, "info")
            title = item.attrib.get("pluginName", "Unknown")

            # Deduplicate
            existing = db.query(models.Finding).filter(
                models.Finding.pid == pid,
                models.Finding.host_id == host.id,
                models.Finding.title == title,
            ).first()
            if existing:
                findings_skipped += 1
                continue

            description = ""
            recommendation = ""
            cve = ""
            cvss = ""

            desc_el = item.find("description")
            if desc_el is not None:
                description = (desc_el.text or "").strip()

            sol_el = item.find("solution")
            if sol_el is not None:
                recommendation = (sol_el.text or "").strip()

            cve_el = item.find("cve")
            if cve_el is not None:
                cve = (cve_el.text or "").strip()

            # Try cvss3 first, then cvss
            cvss3_el = item.find("cvss3_base_score")
            if cvss3_el is not None:
                cvss = (cvss3_el.text or "").strip()
            else:
                cvss_el = item.find("cvss_base_score")
                if cvss_el is not None:
                    cvss = (cvss_el.text or "").strip()

            finding = models.Finding(
                id=new_id("f"),
                pid=pid,
                host_id=host.id,
                title=title,
                severity=severity,
                description=description,
                recommendation=recommendation,
                cve=cve,
                cvss=cvss,
                proof="",
                status="open",
                ts=_now(),
            )
            db.add(finding)
            findings_created += 1

    db.commit()
    return {
        "hosts_created": hosts_created,
        "hosts_updated": hosts_updated,
        "findings_created": findings_created,
        "findings_skipped": findings_skipped,
    }


# ── Burp ──────────────────────────────────────────────────────────────

def _parse_burp(db: Session, pid: str, content: bytes) -> dict:
    hosts_created = 0
    hosts_updated = 0
    findings_created = 0
    findings_skipped = 0

    try:
        root = ET.fromstring(content)
    except ET.ParseError as e:
        raise HTTPException(400, f"Invalid XML: {e}")

    # Support both <issues> root and direct <issue> elements
    issues = list(root.iter("issue"))

    for issue in issues:
        # Host
        host_el = issue.find("host")
        ip = ""
        if host_el is not None:
            ip = host_el.attrib.get("ip", "").strip()
            if not ip:
                ip = (host_el.text or "").strip()

        # Title
        name_el = issue.find("name")
        title = _strip_html((name_el.text or "").strip()) if name_el is not None else "Burp Finding"

        # Severity
        sev_el = issue.find("severity")
        severity_raw = (sev_el.text or "info").strip().lower() if sev_el is not None else "info"
        severity = _BURP_SEVERITY_MAP.get(severity_raw, "info")

        # Description
        description_parts = []
        conf_el = issue.find("confidence")
        if conf_el is not None:
            description_parts.append(f"Confidence: {_strip_html(conf_el.text or '')}")

        detail_el = issue.find("issueDetail")
        if detail_el is not None and detail_el.text:
            description_parts.append(_strip_html(detail_el.text))
        else:
            bg_el = issue.find("issueBackground")
            if bg_el is not None and bg_el.text:
                description_parts.append(_strip_html(bg_el.text))

        description = "\n\n".join(description_parts)

        # Recommendation
        recommendation = ""
        rem_el = issue.find("remediationDetail")
        if rem_el is not None and rem_el.text:
            recommendation = _strip_html(rem_el.text)
        else:
            rem_bg_el = issue.find("remediationBackground")
            if rem_bg_el is not None and rem_bg_el.text:
                recommendation = _strip_html(rem_bg_el.text)

        # Find or create host
        host = None
        if ip:
            host = db.query(models.Host).filter(
                models.Host.pid == pid, models.Host.ip == ip
            ).first()
            if not host:
                host = models.Host(
                    id=new_id("h"),
                    pid=pid,
                    ip=ip,
                    hostname="",
                    os="Unknown",
                    status="unknown",
                    ports=[],
                    services=[],
                    tags=[],
                    notes="",
                    domain="",
                    role="unknown",
                    is_attacker=False,
                    import_source="burp",
                )
                db.add(host)
                db.flush()
                hosts_created += 1
            else:
                hosts_updated += 1

        host_id = host.id if host else None

        # Deduplicate
        existing_q = db.query(models.Finding).filter(
            models.Finding.pid == pid,
            models.Finding.title == title,
        )
        if host_id:
            existing_q = existing_q.filter(models.Finding.host_id == host_id)
        if existing_q.first():
            findings_skipped += 1
            continue

        finding = models.Finding(
            id=new_id("f"),
            pid=pid,
            host_id=host_id,
            title=title,
            severity=severity,
            description=description,
            recommendation=recommendation,
            cve="",
            cvss="",
            proof="",
            status="open",
            ts=_now(),
        )
        db.add(finding)
        findings_created += 1

    db.commit()
    return {
        "hosts_created": hosts_created,
        "hosts_updated": hosts_updated,
        "findings_created": findings_created,
        "findings_skipped": findings_skipped,
    }


# ── Endpoints ─────────────────────────────────────────────────────────

@router.post("/api/projects/{pid}/import/nessus")
async def import_nessus(
    pid: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    check_pid_access(db, pid, user, "findings.create")
    content = await file.read()
    result = _parse_nessus(db, pid, content)
    log_event(db, pid, getattr(user, "username", None), "import", "nessus",
              f"Nessus import: {result['findings_created']} findings, {result['hosts_created']} new hosts",
              result)
    return result


@router.post("/api/projects/{pid}/import/burp")
async def import_burp(
    pid: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    check_pid_access(db, pid, user, "findings.create")
    content = await file.read()
    result = _parse_burp(db, pid, content)
    log_event(db, pid, getattr(user, "username", None), "import", "burp",
              f"Burp import: {result['findings_created']} findings, {result['hosts_created']} new hosts",
              result)
    return result
