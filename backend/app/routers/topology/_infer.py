from pydantic import BaseModel

from ._edge_meta import _ip_in_network


class TopologyLinkDiff(BaseModel):
    source_ip: str
    target_ip: str
    link_type: str = "same_subnet"
    confidence: float = 1.0
    source: str = "nmap"
    label: str = ""
    reason: str = ""


def _get_subnet(ip: str) -> str:
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return "0.0.0.0/24"


def infer_links(hosts: list[dict]) -> list[TopologyLinkDiff]:
    links = []
    subnet_hosts: dict[str, list[str]] = {}
    for h in hosts:
        ip = h.get("ip", "")
        if not ip:
            continue
        subnet = _get_subnet(ip)
        subnet_hosts.setdefault(subnet, []).append(ip)

    seen: set = set()
    for _subnet, ips in subnet_hosts.items():
        if len(ips) < 2:
            continue
        for i, src in enumerate(ips[:8]):
            for dst in ips[i + 1 : 8]:
                key = tuple(sorted([src, dst]))
                if key in seen:
                    continue
                seen.add(key)
                links.append(
                    TopologyLinkDiff(
                        source_ip=src,
                        target_ip=dst,
                        link_type="same_subnet",
                        confidence=0.9,
                        source="nmap",
                    )
                )
    return links


_GW_ROLES = {"router", "firewall", "network_device"}
_GW_TAGS = {"router", "firewall", "fw", "gateway", "pivot", "border"}
_GW_OS = (
    "cisco",
    "juniper",
    "pfsense",
    "opnsense",
    "fortinet",
    "vyos",
    "checkpoint",
    "mikrotik",
    "router",
    "fortigate",
)


def _is_gateway(host: dict) -> bool:
    if (host.get("role") or "").lower() in _GW_ROLES:
        return True
    if {t.lower() for t in (host.get("tags") or [])} & _GW_TAGS:
        return True
    os_l = (host.get("os") or "").lower()
    return any(kw in os_l for kw in _GW_OS)


_GW_IP_SUFFIXES = {1, 2, 254, 253, 252}

_SCOPE_REGION_PALETTE = [
    ("#5b8af5", "#5b8af522"),
    ("#39d353", "#39d3531c"),
    ("#f09a3a", "#f09a3a1c"),
    ("#c07af0", "#c07af01c"),
    ("#6fc8f0", "#6fc8f01c"),
    ("#e8574a", "#e8574a1c"),
]


def _scope_region_colors(cidr: str, in_scope: bool, via_host_id: str = "") -> tuple[str, str]:
    idx = sum(ord(ch) for ch in (cidr or "")) % len(_SCOPE_REGION_PALETTE)
    stroke, fill = _SCOPE_REGION_PALETTE[idx]
    if via_host_id:
        return ("#f09a3a", "#f09a3a18")
    if in_scope:
        return stroke, fill
    return ("#cc2233", "#cc22331a")


def _host_matches_gateway_ip(host: dict, gateway_ip: str) -> bool:
    if not gateway_ip:
        return False
    if (host.get("ip") or "") == gateway_ip:
        return True
    return gateway_ip in {str(ip).strip() for ip in (host.get("ips") or []) if str(ip).strip()}


def _region_center(region: dict) -> tuple[float, float]:
    return (
        float(region.get("x") or 0) + float(region.get("w") or 0) / 2.0,
        float(region.get("y") or 0) + float(region.get("h") or 0) / 2.0,
    )


def _midpoint_in_overlap(a0: float, a_size: float, b0: float, b_size: float) -> float:
    lo = max(a0, b0)
    hi = min(a0 + a_size, b0 + b_size)
    if hi > lo:
        return (lo + hi) / 2.0
    return (a0 + a_size / 2.0 + b0 + b_size / 2.0) / 2.0


def _place_between_regions(region_a: dict, region_b: dict) -> tuple[float, float]:
    ax = float(region_a.get("x") or 0)
    ay = float(region_a.get("y") or 0)
    aw = float(region_a.get("w") or 0)
    ah = float(region_a.get("h") or 0)
    bx = float(region_b.get("x") or 0)
    by = float(region_b.get("y") or 0)
    bw = float(region_b.get("w") or 0)
    bh = float(region_b.get("h") or 0)

    if ax + aw <= bx:
        return (ax + aw + bx) / 2.0, _midpoint_in_overlap(ay, ah, by, bh)
    if bx + bw <= ax:
        return (bx + bw + ax) / 2.0, _midpoint_in_overlap(ay, ah, by, bh)
    if ay + ah <= by:
        return _midpoint_in_overlap(ax, aw, bx, bw), (ay + ah + by) / 2.0
    return _midpoint_in_overlap(ax, aw, bx, bw), (by + bh + ay) / 2.0


def _place_on_region_edge(region: dict, side: str) -> tuple[float, float]:
    x = float(region.get("x") or 0)
    y = float(region.get("y") or 0)
    w = float(region.get("w") or 0)
    h = float(region.get("h") or 0)
    if side == "left":
        return x - 12.0, y + h / 2.0
    if side == "right":
        return x + w + 12.0, y + h / 2.0
    if side == "top":
        return x + w / 2.0, y - 12.0
    return x + w / 2.0, y + h + 12.0


def _host_scope_memberships(host: dict, scope_defs: list[dict]) -> list[str]:
    memberships = []
    all_ips = [
        str(host.get("ip") or "").strip(),
        *[str(ip).strip() for ip in (host.get("ips") or []) if str(ip).strip()],
    ]
    uniq_ips = [ip for ip in dict.fromkeys(all_ips) if ip]
    for scope in scope_defs:
        net_obj = scope.get("net_obj")
        cidr = scope.get("cidr") or ""
        if not net_obj or not cidr:
            continue
        for ip in uniq_ips:
            if _ip_in_network(ip, net_obj):
                memberships.append(cidr)
                break
    return memberships


def _pick_gateway(group: list[dict]) -> dict:
    gw = next((h for h in group if _is_gateway(h)), None)
    if gw is not None:
        return gw

    def _suffix_priority(h: dict) -> int:
        try:
            last = int((h.get("ip") or "").split(".")[-1])
            order = [1, 254, 253, 252, 2]
            return order.index(last) if last in order else len(order)
        except (ValueError, IndexError):
            return 999

    candidates_by_suffix = [h for h in group if _suffix_priority(h) < 999]
    if candidates_by_suffix:
        return min(candidates_by_suffix, key=_suffix_priority)

    best_port_count = max(len(h.get("ports") or []) for h in group)
    if best_port_count > 0:
        port_candidates = [h for h in group if len(h.get("ports") or []) == best_port_count]
        return min(
            port_candidates,
            key=lambda h: tuple(
                int(p) for p in (h.get("ip") or "0.0.0.0").split(".") if p.isdigit()
            ),
        )

    return min(
        group,
        key=lambda h: tuple(int(p) for p in (h.get("ip") or "0.0.0.0").split(".") if p.isdigit()),
    )


def _add_inferred_link(
    src: str,
    dst: str,
    seen: set,
    links: list,
    link_type: str = "same_subnet",
    label: str = "",
    confidence: float = 0.9,
    reason: str = "",
) -> None:
    key = tuple(sorted([src, dst]))
    if key not in seen and src != dst:
        seen.add(key)
        links.append(
            TopologyLinkDiff(
                source_ip=src,
                target_ip=dst,
                link_type=link_type,
                confidence=confidence,
                source="auto",
                label=label,
                reason=reason,
            )
        )


def _build_host_by_ip(hosts: list[dict]) -> dict:
    host_by_ip: dict = {}
    for h in hosts:
        primary_ip = h.get("ip", "")
        if primary_ip:
            host_by_ip[primary_ip] = h
        for extra_ip in h.get("ips") or []:
            if extra_ip:
                host_by_ip[extra_ip] = h
    return host_by_ip


def _get_subnet_for_ip(ip: str, primary_ip: str, host: dict) -> str:
    if ip != primary_ip:
        return _get_subnet(ip)
    return host.get("subnet") or _get_subnet(ip)


def _group_hosts_by_subnet(hosts: list[dict]) -> dict:
    subnet_hosts: dict = {}
    seen_per_subnet: dict = {}
    for h in hosts:
        primary_ip = h.get("ip", "")
        all_ips = list({primary_ip, *(h.get("ips") or [])} - {""})
        if not all_ips:
            continue
        for ip in all_ips:
            subnet = _get_subnet_for_ip(ip, primary_ip, h)
            if not subnet:
                continue
            bucket = seen_per_subnet.setdefault(subnet, set())
            if h.get("id") in bucket:
                continue
            bucket.add(h.get("id") or "")
            entry = dict(h)
            entry["ip"] = ip
            subnet_hosts.setdefault(subnet, []).append(entry)
    return subnet_hosts


def _gw_reason_str(gw: dict, gw_ip: str, manual_gw) -> str:
    gw_hostname = gw.get("hostname", "") or gw_ip
    if manual_gw is not None:
        return f"manual scope gateway {gw_hostname}"
    if _is_gateway(gw):
        return f"gateway role/tag/OS on {gw_hostname}"
    last_octet = gw_ip.split(".")[-1] if gw_ip else ""
    if last_octet in ("1", "2", "254", "253", "252"):
        return f"common gateway IP suffix (.{last_octet}) on {gw_hostname}"
    port_count = len(gw.get("ports") or [])
    return f"most open ports ({port_count}) → hub heuristic on {gw_hostname}"


def _infer_intra_subnet(
    subnet_hosts: dict, seen: set, links: list, manual_gateway_by_subnet: dict, host_by_ip: dict
) -> dict:
    subnet_gw: dict = {}
    for subnet, group in subnet_hosts.items():
        if len(group) < 2:
            continue
        manual_gw_ip = (manual_gateway_by_subnet.get(subnet) or "").strip()
        manual_gw = host_by_ip.get(manual_gw_ip) if manual_gw_ip else None
        gw = manual_gw or _pick_gateway(group)
        gw_ip = gw.get("ip", "")
        if gw_ip:
            subnet_gw[subnet] = gw_ip
        gw_reason = _gw_reason_str(gw, gw_ip, manual_gw)
        for h in group:
            h_ip = h.get("ip", "")
            if h_ip and h_ip != gw_ip:
                _add_inferred_link(
                    gw_ip, h_ip, seen, links, "same_subnet",
                    confidence=0.9, reason=f"same /{subnet} subnet; hub: {gw_reason}",
                )
    return subnet_gw


def _infer_inter_subnet(subnet_gw: dict, isolated_subnets: set, seen: set, links: list) -> None:
    gw_list = [(s, ip) for s, ip in subnet_gw.items()]
    for i, (sa, a) in enumerate(gw_list):
        if sa in isolated_subnets:
            continue
        for sb, b in gw_list[i + 1:]:
            if sb in isolated_subnets:
                continue
            _add_inferred_link(
                a, b, seen, links, "lan", confidence=0.7,
                reason=f"inter-subnet route between {sa} and {sb} (gateway heuristic)",
            )


def infer_links_smart(
    hosts: list[dict],
    manual_gateway_by_subnet: dict[str, str] | None = None,
    isolated_subnets: set[str] | None = None,
) -> list[TopologyLinkDiff]:
    if not hosts:
        return []
    manual_gateway_by_subnet = manual_gateway_by_subnet or {}
    isolated_subnets = isolated_subnets or set()
    host_by_ip = _build_host_by_ip(hosts)
    subnet_hosts = _group_hosts_by_subnet(hosts)
    seen: set = set()
    links: list[TopologyLinkDiff] = []
    subnet_gw = _infer_intra_subnet(subnet_hosts, seen, links, manual_gateway_by_subnet, host_by_ip)
    _infer_inter_subnet(subnet_gw, isolated_subnets, seen, links)
    return links
