import ipaddress
import re
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from .. import models

_CIDR_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _extract_target_networks(target_hint: str) -> list[ipaddress._BaseNetwork]:
    text = (target_hint or '').strip()
    if not text:
        return []
    candidates: list[ipaddress._BaseNetwork] = []
    raw_items = set(_CIDR_RE.findall(text))
    raw_items.update(_IP_RE.findall(text))
    if '://' in text:
        try:
            parsed = urlparse(text)
            if parsed.hostname:
                raw_items.add(parsed.hostname)
        except Exception:
            pass
    for item in raw_items:
        try:
            if '/' in item:
                candidates.append(ipaddress.ip_network(item, strict=False))
            else:
                candidates.append(ipaddress.ip_network(f"{item}/32", strict=False))
        except ValueError:
            continue
    return candidates


def _route_score(route_cidr: str, targets: list[ipaddress._BaseNetwork]) -> int:
    if not route_cidr or not targets:
        return 0
    try:
        route = ipaddress.ip_network(route_cidr, strict=False)
    except ValueError:
        return 0
    score = 0
    for target in targets:
        if target.subnet_of(route) or route.subnet_of(target) or target.overlaps(route):
            score = max(score, route.prefixlen)
    return score


def annotate_targets_with_route_context(pid: str, targets: list[dict], db: Session, target_hint: str = '') -> list[dict]:
    active = db.query(models.PivotObservation).filter(models.PivotObservation.pid == pid, models.PivotObservation.status == 'active').all()
    routes_by_target: dict[str, list[str]] = {}
    for obs in active:
        if not obs.collector_target_id or not obs.route_cidr:
            continue
        routes_by_target.setdefault(obs.collector_target_id, []).append(obs.route_cidr)

    target_networks = _extract_target_networks(target_hint)
    annotated = []
    for target in targets:
        route_cidrs = []
        seen = set()
        for cidr in routes_by_target.get(target.get('id', ''), []):
            if cidr in seen:
                continue
            seen.add(cidr)
            route_cidrs.append(cidr)
        route_score = max((_route_score(cidr, target_networks) for cidr in route_cidrs), default=0)
        annotated.append({
            **target,
            'route_cidrs': route_cidrs,
            'route_count': len(route_cidrs),
            'route_match_score': route_score,
            'route_matched': route_score > 0,
        })
    annotated.sort(key=lambda item: (-int(item.get('route_match_score') or 0), -int(item.get('route_count') or 0), str(item.get('name') or item.get('host') or '')))
    return annotated


def choose_route_aware_target(pid: str, targets: list[dict], db: Session, target_hint: str = '') -> dict | None:
    annotated = annotate_targets_with_route_context(pid, targets, db, target_hint)
    return annotated[0] if annotated else None
