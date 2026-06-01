"""
Structured result schema for normalized job output.

After every job, result_json["structured"] is populated with a normalized
summary that can be used by playbook branching conditions, UI summaries,
and finding candidate surfacing.

All fields are optional. Missing = unknown / not applicable.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class StructuredResult:
    # Overall outcome
    ok: bool = True
    summary: str = ""

    # Authentication / access
    auth_success: bool | None = None
    access_role: str | None = None  # local_admin | domain_admin | user | read | shell

    # Entities touched by this job
    hosts_affected: list = field(default_factory=list)  # host IDs
    creds_affected: list = field(default_factory=list)  # cred IDs

    # State changes applied to project data
    host_changes: list = field(default_factory=list)  # [{"host_id","field","old","new"}]
    cred_changes: list = field(default_factory=list)  # [{"cred_id","field","old","new"}]

    # Analyst hints — not final findings, just candidates
    finding_candidates: list = field(
        default_factory=list
    )  # [{"type","title","severity","host_id","cred_id","details"}]

    # Graph enrichment hints
    graph_updates: list = field(default_factory=list)  # [{"action","from_id","to_id","edge_type"}]

    # Normalized counts (auth_success counts per type)
    counts: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def finding_candidate(
    type: str,
    title: str,
    severity: str = "info",
    host_id: str | None = None,
    cred_id: str | None = None,
    details: str = "",
) -> dict:
    return {
        "type": type,
        "title": title,
        "severity": severity,
        "host_id": host_id,
        "cred_id": cred_id,
        "details": details,
    }
