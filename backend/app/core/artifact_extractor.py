"""
Auto-extracts structured artifacts from job output.
Called from writeback after every finished job.

Artifact types:
  hash_ntlm   — NTLM / NTHash credential material
  hash_krb    — Kerberos TGS (kerberoast) or AS-REP hash
  secret      — cleartext password or token found in output
  file_ref    — path to a file saved by the tool
  stdout_clip — captured output snippet (for notable events)
"""
from __future__ import annotations
import re
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

# ── Patterns ─────────────────────────────────────────────────────────────────

# NTLM hash line: username:RID:LMHASH:NTHASH (impacket / secretsdump / mimikatz)
_NTLM_RE = re.compile(
    r"^([^\s:]+):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::",
    re.MULTILINE,
)

# NTHash only line (some tools): username:NTHash
_NTHASH_ONLY_RE = re.compile(
    r"^([^\s:]+):([0-9a-fA-F]{32})\s*$",
    re.MULTILINE,
)

# Kerberos TGS hash (Kerberoast)
_KRB_TGS_RE = re.compile(
    r"(\$krb5tgs\$\d+\$[^\s]{20,})",
    re.MULTILINE,
)

# Kerberos AS-REP hash (ASREProast)
_KRB_ASREP_RE = re.compile(
    r"(\$krb5asrep\$\d+\$[^\s]{20,})",
    re.MULTILINE,
)

# File saved by tool: common patterns across impacket / netexec / custom scripts
_FILE_SAVED_RE = re.compile(
    r"(?:saved?\s+(?:to|as|in)|writing\s+to|output\s+(?:to|file)|Dumping\s+to)\s+['\"]?(/[^\s'\"]+|\.?/[^\s'\"]+)",
    re.IGNORECASE | re.MULTILINE,
)

# Cleartext passwords from secretsdump / lsassy / mimikatz
_CLEARTEXT_RE = re.compile(
    r"(?:Password|cleartext(?:pwd)?|ClearPassword)\s*[:\t]\s*([^\s][^\n]{0,100})",
    re.IGNORECASE | re.MULTILINE,
)

# Mimikatz-style: * Username / * Password
_MIMI_USER_RE = re.compile(r"\*\s+Username\s*:\s*(\S+)", re.IGNORECASE)
_MIMI_PASS_RE = re.compile(r"\*\s+Password\s*:\s*([^\n\r]+)", re.IGNORECASE)

# NetExec / CME saved loot files
_CME_LOOT_RE = re.compile(
    r"\[\+\]\s+(?:Dumped|Saved|Loot)\s+.*?(\S+\.(?:txt|xml|json|csv|ldb|ntds|dit|keytab))",
    re.IGNORECASE | re.MULTILINE,
)


@dataclass
class ExtractedArtifact:
    artifact_type: str          # hash_ntlm | hash_krb | secret | file_ref | stdout_clip
    loot_type: str              # hash | credential | file | note
    value: str                  # primary value (hash string, password, path)
    description: str = ""
    host_id: Optional[str] = None
    cred_id: Optional[str] = None
    tags: list = field(default_factory=list)


def extract(output: str, job=None) -> list[ExtractedArtifact]:
    """
    Parse job output and return a list of ExtractedArtifact.
    `job` is the SQLAlchemy Job object (optional — used for host_id hints).
    """
    results: list[ExtractedArtifact] = []
    seen: set[str] = set()

    def add(a: ExtractedArtifact):
        key = f"{a.artifact_type}:{a.value[:80]}"
        if key not in seen:
            seen.add(key)
            results.append(a)

    host_id = _job_host_id(job)
    cred_id = _job_cred_id(job)

    # ── NTLM hashes ───────────────────────────────────────────────────────────
    for m in _NTLM_RE.finditer(output):
        username, rid, lm, nt = m.group(1), m.group(2), m.group(3), m.group(4)
        blank_lm = "aad3b435b51404eeaad3b435b51404ee"
        lm_part = "" if lm.lower() == blank_lm else f"{lm}:"
        hash_val = f"{username}:{rid}:{lm_part}{nt}"
        add(ExtractedArtifact(
            artifact_type="hash_ntlm",
            loot_type="hash",
            value=hash_val,
            description=f"NTLM hash for {username}",
            host_id=host_id,
            tags=["ntlm", "hash"],
        ))

    # ── NTHash-only lines (skip if already captured by full NTLM) ─────────────
    for m in _NTHASH_ONLY_RE.finditer(output):
        username, nt = m.group(1), m.group(2)
        val = f"{username}:{nt}"
        add(ExtractedArtifact(
            artifact_type="hash_ntlm",
            loot_type="hash",
            value=val,
            description=f"NT hash for {username}",
            host_id=host_id,
            tags=["ntlm", "hash"],
        ))

    # ── Kerberos TGS ──────────────────────────────────────────────────────────
    for m in _KRB_TGS_RE.finditer(output):
        val = m.group(1)[:2000]
        add(ExtractedArtifact(
            artifact_type="hash_krb",
            loot_type="hash",
            value=val,
            description="Kerberos TGS hash (Kerberoast)",
            host_id=host_id,
            tags=["kerberos", "tgs", "kerberoast"],
        ))

    # ── Kerberos AS-REP ───────────────────────────────────────────────────────
    for m in _KRB_ASREP_RE.finditer(output):
        val = m.group(1)[:2000]
        add(ExtractedArtifact(
            artifact_type="hash_krb",
            loot_type="hash",
            value=val,
            description="Kerberos AS-REP hash (ASREProast)",
            host_id=host_id,
            tags=["kerberos", "asrep", "asreproast"],
        ))

    # ── File references ───────────────────────────────────────────────────────
    for m in _FILE_SAVED_RE.finditer(output):
        path = m.group(1).strip("'\"")
        add(ExtractedArtifact(
            artifact_type="file_ref",
            loot_type="file",
            value=path,
            description=f"Tool saved output to {path}",
            host_id=host_id,
            tags=["file", "output"],
        ))

    for m in _CME_LOOT_RE.finditer(output):
        path = m.group(1)
        add(ExtractedArtifact(
            artifact_type="file_ref",
            loot_type="file",
            value=path,
            description=f"NetExec saved loot: {path}",
            host_id=host_id,
            tags=["file", "netexec"],
        ))

    # ── Cleartext credentials ─────────────────────────────────────────────────
    users = _MIMI_USER_RE.findall(output)
    passwords = _MIMI_PASS_RE.findall(output)
    for user, pw in zip(users, passwords):
        pw = pw.strip()
        if pw and pw.lower() not in ("(null)", "null", ""):
            add(ExtractedArtifact(
                artifact_type="secret",
                loot_type="credential",
                value=f"{user}:{pw}",
                description=f"Cleartext credential for {user} (mimikatz)",
                host_id=host_id,
                cred_id=cred_id,
                tags=["cleartext", "mimikatz"],
            ))

    for m in _CLEARTEXT_RE.finditer(output):
        pw = m.group(1).strip()
        if pw and len(pw) >= 4 and pw.lower() not in ("(null)", "null", "n/a", ""):
            add(ExtractedArtifact(
                artifact_type="secret",
                loot_type="credential",
                value=pw,
                description="Cleartext password extracted from output",
                host_id=host_id,
                cred_id=cred_id,
                tags=["cleartext"],
            ))

    return results


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _job_host_id(job) -> Optional[str]:
    if job is None:
        return None
    rj = job.result_json or {}
    return rj.get("host_id") or (job.request_json or {}).get("host_id") or None


def _job_cred_id(job) -> Optional[str]:
    if job is None:
        return None
    return (job.request_json or {}).get("cred_id") or None
