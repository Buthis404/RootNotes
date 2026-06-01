import ipaddress
from datetime import datetime

from ...core.utils import utcnow

_PORT_88_TCP = "88/tcp"
_PORT_389_TCP = "389/tcp"

_JUNCTION_ROLES = {"router", "firewall", "network_device", "pivot", "jump_host"}
_JUNCTION_TAGS = {"router", "firewall", "gateway", "vpn", "pivot"}
_JUNCTION_KW = ("vpn", "gw", "gateway", "router", "fw", "firewall", "pivot", "tunnel")

_KEY_HOST_ROLES = _JUNCTION_ROLES | {
    "domain_controller",
    "dc",
    "file_server",
    "web_server",
    "database",
    "mail_server",
    "mail",
    "server",
    "jump_host",
    "attacker",
}
_KEY_HOST_TAGS = _JUNCTION_TAGS | {"server", "dc", "domain_controller", "attacker"}


def _is_key_host(h: dict) -> bool:
    if h.get("is_attacker"):
        return True
    role = (h.get("role") or "").lower()
    if role in _KEY_HOST_ROLES:
        return True
    tags = {t.lower() for t in (h.get("tags") or [])}
    if tags & _KEY_HOST_TAGS:
        return True
    return False


_RFC1918_NETS = [
    ipaddress.ip_network((int.from_bytes(bytes([10, 0, 0, 0]), 'big'), 8)),
    ipaddress.ip_network((int.from_bytes(bytes([172, 16, 0, 0]), 'big'), 12)),
    ipaddress.ip_network((int.from_bytes(bytes([192, 168, 0, 0]), 'big'), 16)),
    ipaddress.ip_network((int.from_bytes(bytes([169, 254, 0, 0]), 'big'), 16)),
    ipaddress.ip_network((int.from_bytes(bytes([127, 0, 0, 0]), 'big'), 8)),
]
_PUBLIC_TAGS = {"public", "exposed", "internet", "internet-facing", "edge", "dmz-public"}


def _is_rfc1918(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in n for n in _RFC1918_NETS)
    except ValueError:
        return True


_HN_PATTERNS = (
    (("DC",), "domain_controller"),
    (("EXCHANGE", "MAIL", "MX", "SMTP"), "mail"),
    (("MSSQL", "SQL", "MYSQL", "POSTGRES", "ORACLE"), "database"),
    (("SHPOINT", "SHAREPOINT", "WEB", "WWW", "HTTPD", "NGINX", "APACHE", "IIS"), "web"),
    (("VPN", "GW", "GATEWAY", "FW", "FIREWALL", "ROUTER", "EDGE", "PROXY"), "router"),
)


def _role_from_tags(tags: set) -> str | None:
    if "dc" in tags or "domain-controller" in tags:
        return "domain_controller"
    if tags & {"router", "firewall", "gateway"}:
        return "router"
    if tags & {"database", "db", "mssql", "mysql", "postgres"}:
        return "database"
    if tags & {"mail", "exchange", "smtp"}:
        return "mail"
    if tags & {"web", "webapp", "iis"}:
        return "web"
    return None


def _role_from_hostname_patterns(hostname: str) -> str | None:
    for prefixes, role in _HN_PATTERNS:
        if any(
            hostname == p
            or hostname.startswith(p + "-")
            or hostname.startswith(p + ".")
            or (len(hostname) > len(p) and hostname.startswith(p) and hostname[len(p)].isdigit())
            for p in prefixes
        ):
            return role
    return None


def _role_from_ports(ports: set, domain: str, hostname: str) -> str | None:
    if _PORT_88_TCP in ports and _PORT_389_TCP in ports:
        return "domain_controller"
    if ports & {"1433/tcp", "3306/tcp", "5432/tcp", "1521/tcp", "27017/tcp"}:
        return "database"
    if ports & {"25/tcp", "465/tcp", "587/tcp", "993/tcp", "995/tcp"}:
        return "mail"
    role = _role_from_hostname_patterns(hostname)
    if role:
        return role
    if ports & {"80/tcp", "443/tcp", "8080/tcp", "8443/tcp"}:
        return "web"
    if "445/tcp" in ports and domain:
        return "workstation"
    if "22/tcp" in ports and len(ports) <= 2:
        return "server"
    if domain:
        return "workstation"
    return None


def _auto_assign_host_role(host: "models.Host") -> str | None:
    if host.is_attacker:
        return "attacker"
    tags = {(t or "").lower() for t in (host.tags or [])}
    role = _role_from_tags(tags)
    if role:
        return role
    return _role_from_ports(
        set(host.ports or []),
        (host.domain or "").lower(),
        (host.hostname or "").upper(),
    )


def _edge_action_tags(source: str, activity_type: str = "") -> dict:
    src = (source or "").lower()
    if src == "cred_validation":
        return {
            "mitre_techniques": ["T1078"],
            "noise_level": "med",
            "kill_chain_stage": "lateral_movement",
        }
    if src == "bulk_exec":
        return {
            "mitre_techniques": ["T1059"],
            "noise_level": "high",
            "kill_chain_stage": "execution",
        }
    if src == "host_activity":
        at = (activity_type or "").lower()
        if at == "c2":
            return {
                "mitre_techniques": ["T1071"],
                "noise_level": "low",
                "kill_chain_stage": "command_and_control",
            }
        if at == "lateral":
            return {
                "mitre_techniques": ["T1021"],
                "noise_level": "med",
                "kill_chain_stage": "lateral_movement",
            }
        if at == "postex":
            return {
                "mitre_techniques": ["T1059"],
                "noise_level": "high",
                "kill_chain_stage": "execution",
            }
        return {
            "mitre_techniques": ["T1059"],
            "noise_level": "med",
            "kill_chain_stage": "execution",
        }
    if src == "pivot_observation":
        return {
            "mitre_techniques": ["T1090"],
            "noise_level": "low",
            "kill_chain_stage": "command_and_control",
        }
    return {}


def _decay_confidence(c0: float, ts_iso: str, tau_days: float) -> tuple[float, bool]:
    if not tau_days or tau_days <= 0 or not ts_iso:
        return c0, False
    try:
        ts = datetime.fromisoformat(ts_iso.replace("Z", "+00:00"))
        if ts.tzinfo is not None:
            ts = ts.replace(tzinfo=None)
        delta_days = max(0.0, (utcnow() - ts).total_seconds() / 86400.0)
    except (ValueError, TypeError):
        return c0, False
    import math

    c = c0 * math.exp(-delta_days / tau_days)
    return c, c < 0.4


def _ip_in_network(ip: str, net: ipaddress.IPv4Network) -> bool:
    try:
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


def _score_pivot_candidate(
    h: dict, entry_nets: list, remote_net, excluded_ips: set
) -> int | None:
    ip = h.get("ip") or ""
    if not ip or ip in excluded_ips:
        return None
    if not any(_ip_in_network(ip, en) for en in entry_nets):
        return None
    if _ip_in_network(ip, remote_net):
        return None
    role = (h.get("role") or "").lower()
    tags = {t.lower() for t in (h.get("tags") or [])}
    hn_low = (h.get("hostname") or "").lower()
    is_junction = (
        role in _JUNCTION_ROLES
        or tags & _JUNCTION_TAGS
        or any(kw in hn_low for kw in _JUNCTION_KW)
    )
    if not is_junction:
        return None
    score = sum(10 for kw in ("vpn", "tunnel") if kw in hn_low)
    score += 5 if role in _JUNCTION_ROLES else 0
    return score


def _find_pivot_host(
    remote_net: ipaddress.IPv4Network,
    scope_region_defs: list[dict],
    hosts_meta: list[dict],
    excluded_ips: set[str],
) -> dict | None:
    entry_nets = [
        sr["net_obj"] for sr in scope_region_defs if sr.get("is_entry") and sr.get("net_obj")
    ]
    if not entry_nets:
        entry_nets = [sr["net_obj"] for sr in scope_region_defs if sr.get("net_obj")]

    candidates = []
    for h in hosts_meta:
        score = _score_pivot_candidate(h, entry_nets, remote_net, excluded_ips)
        if score is not None:
            candidates.append((score, h))

    if not candidates:
        return None
    return max(candidates, key=lambda x: x[0])[1]
