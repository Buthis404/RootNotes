"""
Network topology layout engine — 4-phase hierarchical algorithm.

Phase 1  Group hosts by subnet, classify device tier within each cluster.
Phase 2  Build meta-graph of subnets; assign depth-from-perimeter layers
         (Sugiyama-style) and order clusters within each layer via the
         barycenter heuristic to minimise inter-layer edge crossings.
Phase 3  Compute cluster bounding boxes; assign cluster canvas origins.
Phase 4  Place nodes inside each cluster in tier rows (gateway → server →
         endpoint), centred and sorted by connectivity. Apply manual
         position overrides last.
"""
import ipaddress
import math
from collections import defaultdict
from typing import Optional

# ── Canvas / spacing constants ────────────────────────────────────────
NODE_W         = 160   # horizontal cell width  per node
NODE_H         = 110   # vertical cell height   per node
NODES_PER_ROW  = 4     # max nodes in one tier row
TIER_GAP       = 50    # vertical gap between tiers inside a cluster
CLUSTER_PAD_X  = 60    # horizontal padding inside cluster bounding box
CLUSTER_PAD_Y  = 50    # vertical   padding inside cluster bounding box
CLUSTER_H_GAP  = 120   # horizontal gap between adjacent clusters (same layer)
CLUSTER_V_GAP  = 180   # vertical   gap between layer rows
CANVAS_LEFT    = 120   # left-edge origin
CANVAS_TOP     = 140   # top-edge origin for the shallowest (internet) layer
ATTACKER_OFFSET= -220  # y-offset above the shallowest layer for attacker cluster


# ── Device tier ───────────────────────────────────────────────────────

_GATEWAY_DTYPES = {"router", "firewall", "switch"}
_GATEWAY_TAGS   = {"gateway", "router", "firewall", "fw", "pivot",
                   "perimeter", "border"}
_GATEWAY_OS     = ("cisco", "juniper", "pfsense", "opnsense", "fortinet",
                   "checkpoint", "palo alto", "mikrotik", "vyos", "asa",
                   "router", "fortigate")
_SERVER_PORTS   = {21, 22, 25, 53, 80, 110, 143, 389, 443, 445, 465,
                   587, 636, 993, 995, 1433, 1521, 2049, 3306, 3389,
                   5432, 5900, 6379, 7001, 8080, 8443, 8888, 9200, 27017}
_ENDPOINT_OS    = ("windows xp", "windows 7", "windows 8", "windows 10",
                   "windows 11", "windows vista", "macos", "macbook")


def _device_tier(host: dict) -> int:
    """
    Classify host into a tier for intra-cluster placement.

      -1  attacker / red-team node  (placed in separate cluster above map)
       0  gateway: router, firewall, switch  (top of cluster)
       1  server: web, db, mail, DC …        (middle)
       2  endpoint: workstation, printer …   (bottom)
    """
    if host.get("is_attacker") or (host.get("role") or "").lower() == "attacker":
        return -1

    dtype   = (host.get("device_type") or host.get("type") or "").lower().strip()
    tags    = {t.lower() for t in (host.get("tags") or [])}
    os_low  = (host.get("os") or "").lower()

    if dtype in _GATEWAY_DTYPES:
        return 0
    if tags & _GATEWAY_TAGS:
        return 0
    if any(kw in os_low for kw in _GATEWAY_OS):
        return 0

    port_nums: set[int] = set()
    for p in host.get("ports") or []:
        try:
            port_nums.add(int(str(p).split("/")[0]))
        except (ValueError, AttributeError):
            pass

    if port_nums & _SERVER_PORTS:
        return 1
    if any(kw in os_low for kw in _ENDPOINT_OS):
        return 2

    return 1  # default: server


# ── Subnet helpers ────────────────────────────────────────────────────

def _host_subnet(host: dict) -> str:
    """Return /24 subnet key for a host (e.g. '10.10.10.0/24')."""
    explicit = (host.get("subnet") or "").strip()
    if explicit and "/" in explicit:
        try:
            net   = ipaddress.ip_network(explicit, strict=False)
            parts = str(net.network_address).split(".")
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except ValueError:
            pass

    ip    = (host.get("ip") or "").strip()
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return "0.0.0.0/24"


def _subnet_depth(subnet_hosts: list) -> int:
    """
    Estimate how far a subnet is from the internet perimeter.

      0  external / internet
      1  DMZ / screened subnet
      2  internal (default for RFC-1918 subnets)
      3  deep internal / segmented (AD, OT, isolated VLAN)
    """
    for h in subnet_hosts:
        tags = {t.lower() for t in (h.get("tags") or [])}
        if tags & {"internet", "external", "public"}:
            return 0
        if tags & {"dmz", "perimeter", "screened", "semi-trusted"}:
            return 1
        if tags & {"ad", "domain", "internal", "corp", "trusted",
                   "ot", "scada", "isolated", "segmented"}:
            return 3

    # All hosts have routable (public) IPs → external
    if subnet_hosts:
        private_count = 0
        for h in subnet_hosts:
            try:
                if ipaddress.ip_address(h.get("ip") or "").is_private:
                    private_count += 1
            except ValueError:
                pass
        if private_count == 0:
            return 0

    return 2  # default: generic internal subnet


# ── Cluster geometry ──────────────────────────────────────────────────

def _cluster_dims(tiers: dict) -> tuple:
    """
    Return (width, height) pixel dimensions of a cluster bounding box.
    tiers: {tier_int: [hosts]}
    """
    max_content_w = 0
    total_content_h = 0
    tier_keys = sorted(tiers.keys())
    for i, tier in enumerate(tier_keys):
        n    = len(tiers[tier])
        cols = min(n, NODES_PER_ROW)
        rows = math.ceil(n / NODES_PER_ROW)
        max_content_w  = max(max_content_w, cols * NODE_W)
        total_content_h += rows * NODE_H
        if i < len(tier_keys) - 1:
            total_content_h += TIER_GAP

    w = max_content_w + 2 * CLUSTER_PAD_X
    h = total_content_h + 2 * CLUSTER_PAD_Y
    return w, h


# ── Barycenter reordering ─────────────────────────────────────────────

def _barycenter_reorder(
    layers: dict,
    existing_nodes: list,
    existing_edges: list,
) -> None:
    """
    Reorder subnets within each layer using the barycenter heuristic
    (one downward sweep) to reduce inter-cluster edge crossings.
    Modifies `layers` in-place.
    """
    # Build ip → subnet lookup from known nodes
    ip_to_sub: dict = {}
    for node in existing_nodes:
        ip = node.get("ip") or ""
        parts = ip.split(".")
        if len(parts) == 4:
            ip_to_sub[ip] = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

    # Subnet adjacency from existing edges
    node_by_id: dict = {n.get("id"): n for n in existing_nodes}
    adj: dict = defaultdict(set)
    for edge in existing_edges:
        src = node_by_id.get(edge.get("from") or edge.get("source") or "")
        dst = node_by_id.get(edge.get("to")   or edge.get("target") or "")
        if not (src and dst):
            continue
        ss = ip_to_sub.get(src.get("ip") or "")
        ds = ip_to_sub.get(dst.get("ip") or "")
        if ss and ds and ss != ds:
            adj[ss].add(ds)
            adj[ds].add(ss)

    sorted_depths  = sorted(layers.keys())
    sub_position: dict = {}

    # Initialise positions for the first layer
    if sorted_depths:
        for i, s in enumerate(layers[sorted_depths[0]]):
            sub_position[s] = float(i)

    # Sweep down: compute barycenter for each subnet from previous layer positions
    for depth in sorted_depths[1:]:
        layer = layers[depth]
        bary: dict = {}
        for subnet in layer:
            prev_pos = [sub_position[n] for n in adj.get(subnet, set()) if n in sub_position]
            bary[subnet] = (sum(prev_pos) / len(prev_pos)) if prev_pos else float("inf")

        layers[depth] = sorted(layer, key=lambda s: (bary.get(s, float("inf")), s))
        for i, s in enumerate(layers[depth]):
            sub_position[s] = float(i)


# ── Main entry point ──────────────────────────────────────────────────

def compute_layout(
    hosts: list,
    existing_nodes: list,
    keep_manual: bool = True,
    existing_edges: Optional[list] = None,
) -> list:
    """
    Compute (x, y) for every host in `hosts`.

    Returns a copy of each host dict enriched with:
      x, y              — canvas coordinates
      auto_positioned   — True if position was computed (not manual)

    Manual positions (existing node with manually_positioned=True) are
    preserved unchanged when keep_manual=True.
    """
    if not hosts:
        return []

    existing_edges = existing_edges or []

    # ── Collect manual positions keyed by host_id or IP ──────────────
    manual: dict = {}
    if keep_manual:
        for node in existing_nodes:
            if not node.get("manually_positioned"):
                continue
            key = node.get("host_id") or node.get("ip") or ""
            if key:
                manual[key] = (float(node.get("x", 0)), float(node.get("y", 0)))

    # ── Separate attackers from regular hosts ─────────────────────────
    attackers: list = []
    regular:   list = []
    for h in hosts:
        (attackers if _device_tier(h) == -1 else regular).append(h)

    # ── Phase 1: Group regular hosts by subnet and tier ───────────────
    # subnet → tier → [hosts]
    subnet_tiers: dict = defaultdict(lambda: defaultdict(list))
    for h in regular:
        subnet_tiers[_host_subnet(h)][_device_tier(h)].append(h)

    # ── Phase 2: Assign depth to each subnet ─────────────────────────
    depth_of: dict = {}
    for subnet, tiers in subnet_tiers.items():
        flat = [h for hs in tiers.values() for h in hs]
        depth_of[subnet] = _subnet_depth(flat)

    layers: dict = defaultdict(list)
    for subnet, depth in depth_of.items():
        layers[depth].append(subnet)

    # ── Phase 2b: Order subnets within each layer ─────────────────────
    if existing_edges:
        _barycenter_reorder(layers, existing_nodes, existing_edges)
    else:
        for depth in layers:
            layers[depth].sort()   # deterministic alphabetical fallback

    # ── Phase 3: Assign cluster origins ──────────────────────────────
    cluster_dims: dict = {s: _cluster_dims(t) for s, t in subnet_tiers.items()}

    sorted_depths = sorted(layers.keys())

    # Y origin per depth layer (shallowest = smallest Y = top of canvas)
    layer_y: dict = {}
    y_cursor = CANVAS_TOP
    for depth in sorted_depths:
        layer_subs = layers[depth]
        max_h      = max((cluster_dims[s][1] for s in layer_subs), default=0)
        layer_y[depth] = y_cursor
        y_cursor += max_h + CLUSTER_V_GAP

    # X origin per cluster within its layer
    cluster_origin: dict = {}
    for depth in sorted_depths:
        x_cursor = CANVAS_LEFT
        for subnet in layers[depth]:
            w, h = cluster_dims[subnet]
            cluster_origin[subnet] = (x_cursor, layer_y[depth])
            x_cursor += w + CLUSTER_H_GAP

    # ── Phase 4: Place nodes inside each cluster ──────────────────────
    result: list = []

    for subnet, tiers in subnet_tiers.items():
        ox, oy     = cluster_origin.get(subnet, (CANVAS_LEFT, CANVAS_TOP))
        cw, _      = cluster_dims[subnet]
        y_cursor_t = oy + CLUSTER_PAD_Y

        for tier in sorted(tiers.keys()):          # 0 → 1 → 2  (top to bottom)
            tier_hosts = sorted(
                tiers[tier],
                key=lambda h: (-len(h.get("ports") or []), h.get("ip") or ""),
            )
            n    = len(tier_hosts)
            rows = math.ceil(n / NODES_PER_ROW)

            for row_idx in range(rows):
                row_slice  = tier_hosts[row_idx * NODES_PER_ROW:(row_idx + 1) * NODES_PER_ROW]
                row_len    = len(row_slice)
                row_w      = row_len * NODE_W
                # Centre the row inside the cluster
                row_x0 = ox + CLUSTER_PAD_X + max(0, (cw - 2 * CLUSTER_PAD_X - row_w) // 2)

                for col_idx, h in enumerate(row_slice):
                    h_id = h.get("id") or h.get("ip") or ""
                    if h_id in manual:
                        x, y = manual[h_id]
                        auto = False
                    else:
                        x    = row_x0 + col_idx * NODE_W + NODE_W // 2
                        y    = y_cursor_t + row_idx * NODE_H + NODE_H // 2
                        auto = True
                    result.append({**h, "x": x, "y": y, "auto_positioned": auto})

            y_cursor_t += rows * NODE_H + TIER_GAP

    # ── Place attacker cluster above the shallowest layer ────────────
    if attackers:
        min_y      = min((oy for _, oy in cluster_origin.values()), default=CANVAS_TOP)
        att_y      = max(40, min_y + ATTACKER_OFFSET)
        att_x0     = CANVAS_LEFT
        for i, h in enumerate(attackers):
            h_id = h.get("id") or h.get("ip") or ""
            if h_id in manual:
                x, y = manual[h_id]
                auto = False
            else:
                x    = att_x0 + i * NODE_W + NODE_W // 2
                y    = att_y
                auto = True
            result.append({**h, "x": x, "y": y, "auto_positioned": auto})

    return result
