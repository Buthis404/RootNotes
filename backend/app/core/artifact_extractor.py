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

import hashlib
import re
from dataclasses import dataclass, field

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

# Mimikatz-style: * Username / * Password
_MIMI_USER_RE = re.compile(r"\*\s+Username\s*:\s*(\S+)", re.IGNORECASE)
_MIMI_PASS_RE = re.compile(r"\*\s+Password\s*:\s*([^\n\r]+)", re.IGNORECASE)


@dataclass
class ExtractedArtifact:
    artifact_type: str  # hash_ntlm | hash_krb | secret | file_ref | stdout_clip
    loot_type: str  # hash | credential | file | note
    value: str  # primary value (hash string, password, path)
    description: str = ""
    host_id: str | None = None
    cred_id: str | None = None
    tags: list = field(default_factory=list)


def _add_artifact(seen: set, results: list, a: ExtractedArtifact) -> None:
    key = f"{a.artifact_type}:{a.value[:80]}"
    if key not in seen:
        seen.add(key)
        results.append(a)


def _extract_mimikatz_creds(output: str, host_id, cred_id, seen: set, results: list) -> None:
    users = _MIMI_USER_RE.findall(output)
    passwords = _MIMI_PASS_RE.findall(output)
    for user, pw in zip(users, passwords):
        pw = pw.strip()
        if pw and pw.lower() not in ("(null)", "null", ""):
            _add_artifact(seen, results, ExtractedArtifact(
                artifact_type="secret",
                loot_type="credential",
                value=f"{user}:{pw}",
                description=f"Cleartext credential for {user} (mimikatz)",
                host_id=host_id,
                cred_id=cred_id,
                tags=["cleartext", "mimikatz"],
            ))


def _extract_cleartext_creds(output: str, host_id, cred_id, seen: set, results: list) -> None:
    markers = ("password", "cleartextpwd", "cleartext", "clearpassword")
    for line in output.splitlines():
        line_lc = line.lower()
        if not any(marker in line_lc for marker in markers):
            continue
        sep = None
        if ":" in line:
            sep = ":"
        elif "\t" in line:
            sep = "\t"
        if not sep:
            continue
        _, _, candidate = line.partition(sep)
        pw = candidate.strip()
        if pw and len(pw) >= 4 and pw.lower() not in ("(null)", "null", "n/a", ""):
            _add_artifact(seen, results, ExtractedArtifact(
                artifact_type="secret",
                loot_type="credential",
                value=pw,
                description="Cleartext password extracted from output",
                host_id=host_id,
                cred_id=cred_id,
                tags=["cleartext"],
            ))


def _extract_ntlm_hashes(output: str, host_id, seen: set, results: list) -> None:
    for m in _NTLM_RE.finditer(output):
        username, rid, lm, nt = m.group(1), m.group(2), m.group(3), m.group(4)
        blank_lm = "aad3b435b51404eeaad3b435b51404ee"
        lm_part = "" if lm.lower() == blank_lm else f"{lm}:"
        hash_val = f"{username}:{rid}:{lm_part}{nt}"
        _add_artifact(seen, results, ExtractedArtifact(
            artifact_type="hash_ntlm",
            loot_type="hash",
            value=hash_val,
            description=f"NTLM hash for {username}",
            host_id=host_id,
            tags=["ntlm", "hash"],
        ))


def _extract_nthash_only(output: str, host_id, seen: set, results: list) -> None:
    for m in _NTHASH_ONLY_RE.finditer(output):
        username, nt = m.group(1), m.group(2)
        _add_artifact(seen, results, ExtractedArtifact(
            artifact_type="hash_ntlm",
            loot_type="hash",
            value=f"{username}:{nt}",
            description=f"NT hash for {username}",
            host_id=host_id,
            tags=["ntlm", "hash"],
        ))


def _extract_kerberos_hashes(output: str, host_id, seen: set, results: list) -> None:
    for m in _KRB_TGS_RE.finditer(output):
        _add_artifact(seen, results, ExtractedArtifact(
            artifact_type="hash_krb",
            loot_type="hash",
            value=m.group(1)[:2000],
            description="Kerberos TGS hash (Kerberoast)",
            host_id=host_id,
            tags=["kerberos", "tgs", "kerberoast"],
        ))
    for m in _KRB_ASREP_RE.finditer(output):
        _add_artifact(seen, results, ExtractedArtifact(
            artifact_type="hash_krb",
            loot_type="hash",
            value=m.group(1)[:2000],
            description="Kerberos AS-REP hash (ASREProast)",
            host_id=host_id,
            tags=["kerberos", "asrep", "asreproast"],
        ))


def _extract_file_refs(output: str, host_id, seen: set, results: list) -> None:
    save_markers = ("saved to", "saved as", "saved in", "writing to", "output to", "output file", "dumping to")
    for line in output.splitlines():
        line_lc = line.lower()
        if not any(marker in line_lc for marker in save_markers):
            continue
        path = next((token.strip("'\"") for token in line.split() if token.startswith(("/", "./"))), None)
        if not path:
            continue
        _add_artifact(seen, results, ExtractedArtifact(
            artifact_type="file_ref",
            loot_type="file",
            value=path,
            description=f"Tool saved output to {path}",
            host_id=host_id,
            tags=["file", "output"],
        ))

    loot_suffixes = (".txt", ".xml", ".json", ".csv", ".ldb", ".ntds", ".dit", ".keytab")
    for line in output.splitlines():
        line_lc = line.lower()
        if "[+]" not in line or not any(word in line_lc for word in ("dumped", "saved", "loot")):
            continue
        path = next((token for token in line.split() if token.lower().endswith(loot_suffixes)), None)
        if not path:
            continue
        _add_artifact(seen, results, ExtractedArtifact(
            artifact_type="file_ref",
            loot_type="file",
            value=path,
            description=f"NetExec saved loot: {path}",
            host_id=host_id,
            tags=["file", "netexec"],
        ))


def extract(output: str, job=None) -> list[ExtractedArtifact]:
    """
    Parse job output and return a list of ExtractedArtifact.
    `job` is the SQLAlchemy Job object (optional — used for host_id hints).
    """
    results: list[ExtractedArtifact] = []
    seen: set[str] = set()

    host_id = _job_host_id(job)
    cred_id = _job_cred_id(job)

    _extract_ntlm_hashes(output, host_id, seen, results)
    _extract_nthash_only(output, host_id, seen, results)
    _extract_kerberos_hashes(output, host_id, seen, results)
    _extract_file_refs(output, host_id, seen, results)

    # ── Cleartext credentials ─────────────────────────────────────────────────
    _extract_mimikatz_creds(output, host_id, cred_id, seen, results)
    _extract_cleartext_creds(output, host_id, cred_id, seen, results)

    return results


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ── Helpers ───────────────────────────────────────────────────────────────────


def _job_host_id(job) -> str | None:
    if job is None:
        return None
    rj = job.result_json or {}
    return rj.get("host_id") or (job.request_json or {}).get("host_id") or None


def _job_cred_id(job) -> str | None:
    if job is None:
        return None
    return (job.request_json or {}).get("cred_id") or None
