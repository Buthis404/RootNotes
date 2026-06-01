import asyncio
import json
import logging

import httpx
from fastapi import HTTPException

from ...core.utils import utcnow

logger = logging.getLogger(__name__)

_MYTHIC_CALLBACK_FIELDS = """
id
agent_callback_id
host
user
domain
ip
external_ip
os
architecture
pid
process_name
active
integrity_level
description
last_checkin
init_callback
"""

_MYTHIC_CRED_FIELDS = """
id
account
realm
credential_text
type
comment
"""


async def _mythic_auth_headers(cfg: dict, client: httpx.AsyncClient) -> dict[str, str]:
    token = (cfg.get("token") or "").strip()
    if token:
        return {"apitoken": token}
    username = cfg.get("username") or "mythic_admin"
    password = cfg.get("password", "")
    url = cfg["url"].rstrip("/")
    r = await client.post(
        f"{url}/auth",
        json={"username": username, "password": password, "scripting_version": "0.1"},
    )
    r.raise_for_status()
    data = r.json()
    jwt = data.get("access_token") or data.get("token") or ""
    if not jwt:
        raise HTTPException(400, "Mythic login: no access_token in response")
    return {"Authorization": f"Bearer {jwt}"}


async def _mythic_graphql(cfg: dict, client: httpx.AsyncClient, query: str, headers: dict) -> dict:
    url = cfg["url"].rstrip("/")
    r = await client.post(
        f"{url}/graphql/",
        json={"query": query},
        headers=headers,
    )
    r.raise_for_status()
    data = r.json()
    if data.get("errors"):
        raise HTTPException(400, f"Mythic GraphQL error: {data['errors']}")
    return data.get("data", {})


def _mythic_parse_ip(cb: dict) -> str:
    ip = (cb.get("ip") or "").strip()
    if ip.startswith("[") and ip.endswith("]"):
        try:
            arr = json.loads(ip)
            if isinstance(arr, list) and arr:
                ip = str(arr[0]).strip()
        except Exception as e:
            logger.debug("could not parse Mythic callback ip %r: %s", ip, e)
    return ip or (cb.get("external_ip") or "").strip()


def _mythic_cb_note(cb: dict) -> str:
    parts = []
    if cb.get("description"):
        parts.append(cb["description"])
    if cb.get("integrity_level") is not None:
        parts.append(f"Integrity: {cb['integrity_level']}")
    if cb.get("process_name"):
        parts.append(f"Process: {cb['process_name']} (PID {cb.get('pid', '?')})")
    if cb.get("last_checkin"):
        parts.append(f"Last check-in: {cb['last_checkin']}")
    return "\n".join(parts)


def _mythic_cb_to_host(cb: dict) -> dict | None:
    if not cb:
        return None
    ip = _mythic_parse_ip(cb)
    if not ip:
        return None
    alive = bool(cb.get("active", True))
    return {
        "ip": ip,
        "hostname": (cb.get("host") or "").strip(),
        "os": (cb.get("os") or "").strip(),
        "domain": (cb.get("domain") or "").strip(),
        "username": (cb.get("user") or "").strip(),
        "arch": (cb.get("architecture") or "").strip(),
        "process": (cb.get("process_name") or "").strip(),
        "pid": cb.get("pid"),
        "alive": alive,
        "beacon_id": str(cb.get("agent_callback_id") or cb.get("id") or "") if alive else "",
        "note": _mythic_cb_note(cb),
        "source": "mythic",
    }


def _mythic_cred_result(c: dict) -> dict | None:
    if not c:
        return None
    account = (c.get("account") or "").strip()
    if not account:
        return None
    ctype_raw = (c.get("type") or "plaintext").lower()
    ctype = (
        "hash" if ("hash" in ctype_raw or "ntlm" in ctype_raw or "kerberos" in ctype_raw) else "plain"
    )
    return {
        "username": account,
        "secret": c.get("credential_text") or "",
        "type": ctype,
        "realm": (c.get("realm") or "").strip(),
        "host": "",
        "source": "mythic",
    }


async def _mythic_sync(cfg: dict) -> dict:
    async with httpx.AsyncClient(verify=cfg.get("verify_ssl", False), timeout=30) as client:
        headers = await _mythic_auth_headers(cfg, client)
        query = (
            "query RootNotesSync {"
            f"  callback {{ {_MYTHIC_CALLBACK_FIELDS} }}"
            f"  credential {{ {_MYTHIC_CRED_FIELDS} }}"
            "}"
        )
        data = await _mythic_graphql(cfg, client, query, headers)

    callbacks = data.get("callback") or []
    creds_raw = data.get("credential") or []
    result_hosts = [h for cb in callbacks if (h := _mythic_cb_to_host(cb))]
    result_creds = [c for item in creds_raw if (c := _mythic_cred_result(item))]
    return {"hosts": result_hosts, "creds": result_creds}


async def _mythic_ensure_cb_id(cfg: dict, client, headers: dict, cb_id, callback_id: str) -> int:
    if cb_id is not None:
        return cb_id
    lookup = await _mythic_graphql(
        cfg,
        client,
        f'query {{ callback(where: {{agent_callback_id: {{_eq: "{callback_id}"}} }}) {{ id }} }}',
        headers,
    )
    rows = lookup.get("callback") or []
    if not rows:
        raise HTTPException(404, f"Mythic callback {callback_id!r} not found")
    return rows[0]["id"]


async def _mythic_poll_task(cfg: dict, client, headers: dict, task_db_id: int, timeout_seconds: int) -> dict | None:
    started = utcnow()
    latest = None
    while (utcnow() - started).total_seconds() < max(3, timeout_seconds):
        poll_q = (
            "query RootNotesPollTask {"
            f"  task(where: {{id: {{_eq: {task_db_id}}} }}) {{"
            "    id status completed stdout stderr"
            "    responses(order_by: {sequence_number: asc}) { response_text is_error }"
            "  }"
            "}"
        )
        poll_data = await _mythic_graphql(cfg, client, poll_q, headers)
        rows = poll_data.get("task") or []
        if rows:
            latest = rows[0]
            if latest.get("completed") or (latest.get("status") or "").lower() in ("completed", "error"):
                break
        await asyncio.sleep(0.8)
    return latest


async def _mythic_execute(
    cfg: dict,
    callback_id: str,
    commandline: str,
    wait_for_output: bool = True,
    timeout_seconds: int = 12,
) -> dict:
    command = "shell"
    params = commandline
    stripped = commandline.lstrip()
    if stripped.startswith("!"):
        parts = stripped[1:].split(" ", 1)
        command = parts[0]
        params = parts[1] if len(parts) > 1 else ""

    cb_id = _mythic_resolve_callback_db_id(callback_id)

    async with httpx.AsyncClient(
        verify=cfg.get("verify_ssl", False), timeout=max(30, timeout_seconds + 5)
    ) as client:
        headers = await _mythic_auth_headers(cfg, client)
        cb_id = await _mythic_ensure_cb_id(cfg, client, headers, cb_id, callback_id)

        params_json = json.dumps(params)
        mutation = (
            "mutation RootNotesCreateTask {"
            f'  createTask(callback_id: {cb_id}, command: "{command}", params: {params_json}) {{'
            "    id display_id status error"
            "  }"
            "}"
        )
        data = await _mythic_graphql(cfg, client, mutation, headers)
        out = data.get("createTask") or {}
        if out.get("error"):
            raise HTTPException(400, f"Mythic createTask error: {out['error']}")
        task_db_id = out.get("id")
        result = {
            "accepted": True,
            "task_id": task_db_id,
            "display_id": out.get("display_id"),
            "commandline": commandline,
            "command": command,
            "agent_id": callback_id,
        }
        if not wait_for_output or not task_db_id:
            return result

        latest = await _mythic_poll_task(cfg, client, headers, task_db_id, timeout_seconds)
        if latest:
            responses = latest.get("responses") or []
            output_parts = [r.get("response_text") or "" for r in responses]
            if latest.get("stdout"):
                output_parts.append(latest["stdout"])
            result["output"] = "\n".join(p for p in output_parts if p)
            result["task"] = latest
        return result


def _mythic_resolve_callback_db_id(callback_id: str) -> int | None:
    try:
        return int(callback_id)
    except (TypeError, ValueError):
        return None


def _build_mythic_task_dict(t: dict) -> dict:
    responses = t.get("responses") or []
    output_parts = [r.get("response_text") or "" for r in responses]
    if t.get("stdout"):
        output_parts.append(t["stdout"])
    return {
        "task_id": t.get("id"),
        "display_id": t.get("display_id"),
        "cmdline": f"{t.get('command_name') or ''} {t.get('params') or ''}".strip(),
        "completed": bool(t.get("completed")),
        "text": "\n".join(p for p in output_parts if p),
        "message": "",
        "msg_type": t.get("status") or "",
        "start_time": t.get("timestamp") or "",
        "finish_time": "",
        "computer": "",
        "user": (t.get("operator") or {}).get("username") or "",
        "raw": t,
    }


async def _mythic_fetch_agent_tasks(cfg: dict, callback_id: str, limit: int = 30) -> list[dict]:
    cb_id = _mythic_resolve_callback_db_id(callback_id)
    async with httpx.AsyncClient(verify=cfg.get("verify_ssl", False), timeout=30) as client:
        headers = await _mythic_auth_headers(cfg, client)
        if cb_id is None:
            lookup = await _mythic_graphql(
                cfg,
                client,
                f'query {{ callback(where: {{agent_callback_id: {{_eq: "{callback_id}"}} }}) {{ id }} }}',
                headers,
            )
            rows = lookup.get("callback") or []
            if not rows:
                return []
            cb_id = rows[0]["id"]

        query = (
            "query RootNotesAgentTasks {"
            f"  task(where: {{callback_id: {{_eq: {cb_id}}} }},"
            f"    order_by: {{timestamp: desc}}, limit: {max(1, min(limit, 100))}) {{"
            "    id display_id command_name params status completed timestamp stdout stderr"
            "    responses(order_by: {sequence_number: asc}, limit: 50) { response_text is_error }"
            "    operator { username }"
            "  }"
            "}"
        )
        data = await _mythic_graphql(cfg, client, query, headers)
    rows = data.get("task") or []
    return [_build_mythic_task_dict(t) for t in rows]


async def _mythic_live_agents(cfg: dict) -> list[dict]:
    async with httpx.AsyncClient(verify=cfg.get("verify_ssl", False), timeout=30) as client:
        headers = await _mythic_auth_headers(cfg, client)
        query = "query RootNotesLiveAgents {" f"  callback {{ {_MYTHIC_CALLBACK_FIELDS} }}" "}"
        data = await _mythic_graphql(cfg, client, query, headers)
    callbacks = data.get("callback") or []
    result = []
    for cb in callbacks:
        if not cb:
            continue
        ip = _mythic_parse_ip(cb)
        alive = bool(cb.get("active", True))
        result.append(
            {
                "ip": ip,
                "hostname": (cb.get("host") or "").strip(),
                "username": (cb.get("user") or "").strip(),
                "domain": (cb.get("domain") or "").strip(),
                "os": (cb.get("os") or "").strip(),
                "arch": (cb.get("architecture") or "").strip(),
                "process": (cb.get("process_name") or "").strip(),
                "beacon_id": str(cb.get("agent_callback_id") or cb.get("id") or ""),
                "listener": "",
                "alive": alive,
                "mark": "alive" if alive else "dead",
                "last_seen": cb.get("last_checkin") or "",
            }
        )
    return result
