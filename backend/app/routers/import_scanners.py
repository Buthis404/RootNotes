"""
Scanner import endpoints.

POST /api/projects/{pid}/import/nessus  — import .nessus XML file
POST /api/projects/{pid}/import/burp    — import Burp Suite XML file
"""

import logging
import re
import xml.etree.ElementTree as ET

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from typing import Annotated
from sqlalchemy.orm import Session

from .. import models
from ..core.access import check_pid_access
from ..core.deps import get_current_user
from ..core.events import log_event
from ..core.utils import new_id, ts_now
from ..database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(tags=["import_scanners"])


def _now() -> str:
    return ts_now()


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


def _parse_nessus_host_tags(report_host) -> tuple[str, str, str]:
    """Extract (ip, hostname, os) from a Nessus ReportHost element."""
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
    return ip, hostname, os_str


def _upsert_nessus_host(db: "Session", pid: str, ip: str, hostname: str, os_str: str):
    """Find or create host; return (host, was_created)."""
    host = db.query(models.Host).filter(models.Host.pid == pid, models.Host.ip == ip).first()
    if host:
        if hostname and not host.hostname:
            host.hostname = hostname
        if os_str and not host.os:
            host.os = os_str
        return host, False
    host = models.Host(
        id=new_id("h"), pid=pid, ip=ip, hostname=hostname or "", os=os_str or "Unknown",
        status="unknown", ports=[], services=[], tags=[], notes="", domain="",
        role="unknown", is_attacker=False, import_source="nessus",
    )
    db.add(host)
    db.flush()
    return host, True


def _parse_nessus_item_data(item) -> tuple[str, str, str, str]:
    description = (item.findtext("description") or "").strip()
    recommendation = (item.findtext("solution") or "").strip()
    cve = (item.findtext("cve") or "").strip()
    cvss = (item.findtext("cvss3_base_score") or "").strip()
    if not cvss:
        cvss = (item.findtext("cvss_base_score") or "").strip()
    return description, recommendation, cve, cvss


def _process_nessus_items(db: "Session", pid: str, host, report_host) -> tuple[int, int]:
    created = skipped = 0
    for item in report_host.iter("ReportItem"):
        if item.attrib.get("severity", "0") == "0":
            skipped += 1
            continue
        severity = _NESSUS_SEVERITY_MAP.get(item.attrib.get("severity", "0"), "info")
        title = item.attrib.get("pluginName", "Unknown")
        existing = db.query(models.Finding).filter(
            models.Finding.pid == pid, models.Finding.host_id == host.id,
            models.Finding.title == title,
        ).first()
        if existing:
            skipped += 1
            continue
        description, recommendation, cve, cvss = _parse_nessus_item_data(item)
        db.add(models.Finding(
            id=new_id("f"), pid=pid, host_id=host.id, title=title, severity=severity,
            description=description, recommendation=recommendation, cve=cve, cvss=cvss,
            proof="", status="open", ts=_now(),
        ))
        created += 1
    return created, skipped


def _parse_nessus(db: Session, pid: str, content: bytes) -> dict:
    hosts_created = hosts_updated = findings_created = findings_skipped = 0
    try:
        root = ET.fromstring(content)
    except ET.ParseError as e:
        raise HTTPException(400, f"Invalid XML: {e}")

    for report_host in root.iter("ReportHost"):
        ip, hostname, os_str = _parse_nessus_host_tags(report_host)
        if not ip:
            continue
        host, created = _upsert_nessus_host(db, pid, ip, hostname, os_str)
        if created:
            hosts_created += 1
        else:
            hosts_updated += 1
        fc, fs = _process_nessus_items(db, pid, host, report_host)
        findings_created += fc
        findings_skipped += fs

    db.commit()
    return {
        "hosts_created": hosts_created,
        "hosts_updated": hosts_updated,
        "findings_created": findings_created,
        "findings_skipped": findings_skipped,
    }


# ── Burp ──────────────────────────────────────────────────────────────


def _parse_burp_issue_ip(issue) -> str:
    host_el = issue.find("host")
    if host_el is None:
        return ""
    ip = host_el.attrib.get("ip", "").strip()
    if not ip:
        ip = (host_el.text or "").strip()
    return ip


def _parse_burp_issue_title(issue) -> str:
    name_el = issue.find("name")
    return _strip_html((name_el.text or "").strip()) if name_el is not None else "Burp Finding"


def _parse_burp_issue_severity(issue) -> str:
    sev_el = issue.find("severity")
    severity_raw = (sev_el.text or "info").strip().lower() if sev_el is not None else "info"
    return _BURP_SEVERITY_MAP.get(severity_raw, "info")


def _parse_burp_issue_description(issue) -> str:
    parts = []
    conf_el = issue.find("confidence")
    if conf_el is not None:
        parts.append(f"Confidence: {_strip_html(conf_el.text or '')}")
    detail_el = issue.find("issueDetail")
    if detail_el is not None and detail_el.text:
        parts.append(_strip_html(detail_el.text))
    else:
        bg_el = issue.find("issueBackground")
        if bg_el is not None and bg_el.text:
            parts.append(_strip_html(bg_el.text))
    return "\n\n".join(parts)


def _parse_burp_issue_recommendation(issue) -> str:
    rem_el = issue.find("remediationDetail")
    if rem_el is not None and rem_el.text:
        return _strip_html(rem_el.text)
    rem_bg_el = issue.find("remediationBackground")
    if rem_bg_el is not None and rem_bg_el.text:
        return _strip_html(rem_bg_el.text)
    return ""


def _upsert_burp_host(db: "Session", pid: str, ip: str) -> tuple:
    """Return (host_or_None, hosts_created_delta, hosts_updated_delta)."""
    if not ip:
        return None, 0, 0
    host = db.query(models.Host).filter(models.Host.pid == pid, models.Host.ip == ip).first()
    if not host:
        host = models.Host(
            id=new_id("h"), pid=pid, ip=ip, hostname="", os="Unknown",
            status="unknown", ports=[], services=[], tags=[], notes="",
            domain="", role="unknown", is_attacker=False, import_source="burp",
        )
        db.add(host)
        db.flush()
        return host, 1, 0
    return host, 0, 1


def _parse_burp(db: Session, pid: str, content: bytes) -> dict:
    hosts_created = 0
    hosts_updated = 0
    findings_created = 0
    findings_skipped = 0

    try:
        root = ET.fromstring(content)
    except ET.ParseError as e:
        raise HTTPException(400, f"Invalid XML: {e}")

    for issue in root.iter("issue"):
        ip = _parse_burp_issue_ip(issue)
        title = _parse_burp_issue_title(issue)
        severity = _parse_burp_issue_severity(issue)
        description = _parse_burp_issue_description(issue)
        recommendation = _parse_burp_issue_recommendation(issue)
        host, created, updated = _upsert_burp_host(db, pid, ip)
        hosts_created += created
        hosts_updated += updated
        host_id = host.id if host else None
        existing_q = db.query(models.Finding).filter(
            models.Finding.pid == pid, models.Finding.title == title,
        )
        if host_id:
            existing_q = existing_q.filter(models.Finding.host_id == host_id)
        if existing_q.first():
            findings_skipped += 1
            continue
        db.add(models.Finding(
            id=new_id("f"), pid=pid, host_id=host_id, title=title, severity=severity,
            description=description, recommendation=recommendation,
            cve="", cvss="", proof="", status="open", ts=_now(),
        ))
        findings_created += 1

    db.commit()
    return {
        "hosts_created": hosts_created,
        "hosts_updated": hosts_updated,
        "findings_created": findings_created,
        "findings_skipped": findings_skipped,
    }


# ── Endpoints ─────────────────────────────────────────────────────────


@router.post("/api/projects/{pid}/import/nessus", responses={400: {"description": "Bad request"}})
async def import_nessus(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    file: Annotated[UploadFile, File()],
):
    check_pid_access(db, pid, user, "findings.create")
    content = await file.read()
    result = _parse_nessus(db, pid, content)
    log_event(
        db,
        pid,
        getattr(user, "username", None),
        "import",
        "nessus",
        f"Nessus import: {result['findings_created']} findings, {result['hosts_created']} new hosts",
        result,
    )
    return result


@router.post("/api/projects/{pid}/import/burp", responses={400: {"description": "Bad request"}})
async def import_burp(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    file: Annotated[UploadFile, File()],
):
    check_pid_access(db, pid, user, "findings.create")
    content = await file.read()
    result = _parse_burp(db, pid, content)
    log_event(
        db,
        pid,
        getattr(user, "username", None),
        "import",
        "burp",
        f"Burp import: {result['findings_created']} findings, {result['hosts_created']} new hosts",
        result,
    )
    return result
