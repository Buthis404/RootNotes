"""
Edge semantics classifier — derives `transport` and `kind` from an
edge's existing `type` / `source` / `access_roles` fields.

`transport` answers "if you had to execute on the target via this edge,
which protocol would you use?":
    ssh | smb | winrm | rdp | c2 | ldap | http | mssql | none

`kind` answers "what is this edge logically representing on the map?":
    access  — verified or inferred way to run code as the target user
    lateral — movement between two compromised hosts
    pivot   — network reachability through a junction device
    uplink  — attacker's entry point into the engagement scope
    network — same-subnet / LAN proximity (no execution implied)
    domain  — directory membership (DC ↔ member)
    service — service-graph dependency (web → db, ldap-client → DC)
    other   — fallback when nothing matches

Two derived fields are added at read time (`_edge_to_dict` calls
`classify_edge` and merges the result into the dict). They are NOT
stored — re-deriving keeps existing edges in sync with classifier
updates without a DB migration.
"""
from __future__ import annotations


# Edge type → transport. Single-word match, lowercased.
_TYPE_TO_TRANSPORT: dict[str, str] = {
    # Direct protocol named in edge type
    "ssh": "ssh",
    "ssh_user": "ssh",
    "ssh_admin": "ssh",
    "winrm": "winrm",
    "winrm_admin": "winrm",
    "winrm_user": "winrm",
    "smb": "smb",
    "smb_admin": "smb",
    "smb_user": "smb",
    "rdp": "rdp",
    "rdp_user": "rdp",
    "rdp_admin": "rdp",
    "c2_session": "c2",
    "ldap": "ldap",
    "domain_member": "ldap",
    "mssql": "mssql",
    "mssql_admin": "mssql",
    "http_admin": "http",
    "web": "http",
    "web_admin": "http",
}

# Edge type → kind.
_TYPE_TO_KIND: dict[str, str] = {
    "uplink": "uplink",
    "same_subnet": "network",
    "lan": "network",
    "internet_facing": "network",
    "domain_member": "domain",
    "trust": "domain",
    "can_rdp": "access",
    "allowed_to_delegate": "domain",
    "pivot": "pivot",
    "lateral": "lateral",
    "service_dep": "service",
    "shell": "access",
    "c2_session": "access",
    "ssh": "access",
    "ssh_user": "access",
    "ssh_admin": "access",
    "winrm": "access",
    "winrm_user": "access",
    "winrm_admin": "access",
    "smb": "access",
    "smb_user": "access",
    "smb_admin": "access",
    "rdp": "access",
    "rdp_user": "access",
    "rdp_admin": "access",
    "local_admin": "access",
    "domain_admin": "access",
    "mssql_admin": "access",
    "http_admin": "access",
    "auth_path": "access",
}

# Fallback transport for generic access types where the protocol isn't
# named in the edge type itself. Windows admin paths typically run over
# SMB (PsExec / DCOM / RemComSvc). Domain admin = same (via DC).
_GENERIC_ACCESS_TRANSPORT: dict[str, str] = {
    "local_admin": "smb",
    "domain_admin": "smb",
    "admin": "smb",
    "shell": "",      # shell is too generic — no transport claim
    "auth_path": "",
}


def classify_edge(edge: dict) -> tuple[str, str]:
    """
    Derive (transport, kind) for an edge.

    Lookups are case-insensitive against `edge["type"]`. If the type is
    unrecognised, returns ("", "other").

    A few edges carry an explicit `access_roles` list (set by P1 from
    `CredHostNote.access`). When the canonical `type` is generic
    ("local_admin"/"domain_admin"/"admin"), `access_roles[0]` is checked
    for a more specific transport (e.g. `winrm_admin` → winrm).
    """
    etype = (edge.get("type") or "").strip().lower()

    transport = _TYPE_TO_TRANSPORT.get(etype, "")
    kind = _TYPE_TO_KIND.get(etype, "other")

    # If the type is generic admin/shell, see if access_roles gives a hint
    if not transport and etype in _GENERIC_ACCESS_TRANSPORT:
        transport = _GENERIC_ACCESS_TRANSPORT[etype]
        roles = edge.get("access_roles") or []
        for r in roles:
            sub = _TYPE_TO_TRANSPORT.get(str(r).strip().lower())
            if sub:
                transport = sub
                break

    return transport, kind
