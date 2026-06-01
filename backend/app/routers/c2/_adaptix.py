import asyncio
import logging
import re

import httpx

from ...core.utils import utcnow
from ._integrations import _C2_ENDPOINT_PATH

logger = logging.getLogger(__name__)

_ADAPTIX_DEAD_MARKS = {"terminated", "dead", "killed", "lost", "inactive", "offline"}


def _adaptix_os_for_target(t: dict) -> str:
    os_desc = (t.get("t_os_desk") or "").strip()
    if not os_desc:
        os_int = t.get("t_os", 0)
        os_desc = {1: "Windows", 2: "Linux"}.get(os_int, "")
    return os_desc


def _adaptix_ctx_agent(t: dict, agents_by_id: dict) -> dict:
    for aid in (t.get("t_agents") or []):
        ag = agents_by_id.get(aid)
        if ag and ag.get("a_mark", "") != "Terminated":
            return ag
    return {}


def _adaptix_target_note(t: dict, ctx_agent: dict, domain: str, agent_ids: list) -> str:
    parts = []
    if t.get("t_info"):
        parts.append(t["t_info"])
    if domain:
        parts.append(f"Domain: {domain}")
    if ctx_agent.get("a_process"):
        parts.append(f"Process: {ctx_agent['a_process']} (PID {ctx_agent.get('a_pid', '?')})")
    if ctx_agent.get("a_arch"):
        parts.append(f"Arch: {ctx_agent['a_arch']}")
    if ctx_agent.get("a_impersonated"):
        parts.append(f"Impersonated: {ctx_agent['a_impersonated']}")
    if agent_ids:
        parts.append(f"Agent IDs: {', '.join(agent_ids)}")
    return "\n".join(parts)


def _adaptix_target_to_host(t: dict, agents_by_id: dict) -> dict | None:
    ip = (t.get("t_address") or "").strip()
    if not ip:
        return None
    agent_ids = t.get("t_agents") or []
    ctx_agent = _adaptix_ctx_agent(t, agents_by_id)
    domain = (t.get("t_domain") or "").strip()
    return {
        "ip": ip,
        "hostname": (t.get("t_computer") or "").strip(),
        "os": _adaptix_os_for_target(t),
        "domain": domain,
        "username": (ctx_agent.get("a_username") or "").strip(),
        "arch": (ctx_agent.get("a_arch") or "").strip(),
        "process": (ctx_agent.get("a_process") or "").strip(),
        "pid": ctx_agent.get("a_pid"),
        "alive": t.get("t_alive", True),
        "beacon_id": ",".join(agent_ids) if ctx_agent else "",
        "note": _adaptix_target_note(t, ctx_agent, domain, agent_ids),
        "source": "adaptix",
    }


def _adaptix_agent_to_host(a: dict, seen_ips: set) -> dict | None:
    ip = (a.get("a_internal_ip") or a.get("a_external_ip") or "").strip()
    if not ip or ip in seen_ips:
        return None
    alive = a.get("a_mark", "") != "Terminated"
    domain = (a.get("a_domain") or "").strip()
    note = f"Listener: {a.get('a_listener', '')}" + (f"\nDomain: {domain}" if domain else "")
    return {
        "ip": ip,
        "hostname": (a.get("a_computer") or "").strip(),
        "os": (a.get("a_os_desc") or "").strip(),
        "domain": domain,
        "username": (a.get("a_username") or "").strip(),
        "arch": (a.get("a_arch") or "").strip(),
        "process": (a.get("a_process") or "").strip(),
        "pid": a.get("a_pid"),
        "alive": alive,
        "beacon_id": (a.get("a_id") or "") if alive else "",
        "note": note,
        "source": "adaptix",
    }


def _adaptix_cred_result(c: dict) -> dict | None:
    if not c:
        return None
    uname = (c.get("c_username") or "").strip()
    if not uname:
        return None
    ctype_raw = (c.get("c_type") or "plain").lower()
    ctype = "hash" if ("hash" in ctype_raw or "ntlm" in ctype_raw) else "plain"
    return {
        "username": uname,
        "secret": c.get("c_password") or "",
        "type": ctype,
        "realm": (c.get("c_realm") or "").strip(),
        "host": (c.get("c_host") or "").strip(),
        "source": "adaptix",
    }


async def _adaptix_fetch_targets_dict(client, base: str, headers: dict) -> dict:
    targets_by_id: dict = {}
    try:
        t_r = await client.get(f"{base}/targets/list", headers=headers)
        if t_r.status_code == 200:
            tlist = t_r.json()
            if isinstance(tlist, list):
                for t in tlist:
                    tid = t.get("t_target_id")
                    if tid:
                        targets_by_id[tid] = t
    except Exception as e:
        logger.debug("Adaptix targets/list fetch failed: %s", e)
    return targets_by_id


async def _adaptix_fetch_raw_creds_list(client, base: str, headers: dict) -> list:
    try:
        c_r = await client.get(f"{base}/creds/list", headers=headers)
        if c_r.status_code == 200:
            cdata = c_r.json()
            if isinstance(cdata, list):
                return cdata
    except Exception as e:
        logger.debug("Adaptix creds/list fetch failed: %s", e)
    return []


async def _adaptix_sync(cfg: dict) -> dict:
    url = cfg["url"].rstrip("/")
    ep = cfg.get("endpoint", _C2_ENDPOINT_PATH).rstrip("/") or _C2_ENDPOINT_PATH
    base = f"{url}{ep}"
    token = cfg.get("token", "")

    async with httpx.AsyncClient(verify=cfg.get("verify_ssl", False), timeout=30) as client:
        if not token:
            login_r = await client.post(
                f"{base}/login",
                json={
                    "username": cfg.get("username") or "operator",
                    "password": cfg.get("password", ""),
                    "version": "",
                },
            )
            login_r.raise_for_status()
            token = login_r.json().get("access_token") or login_r.json().get("token") or ""

        headers = {"Authorization": f"Bearer {token}"}
        targets_by_id = await _adaptix_fetch_targets_dict(client, base, headers)

        agents_r = await client.get(f"{base}/agent/list", headers=headers)
        agents_r.raise_for_status()
        agents = agents_r.json()
        if not isinstance(agents, list):
            agents = []
        agents_by_id = {a["a_id"]: a for a in agents if a.get("a_id")}
        raw_creds = await _adaptix_fetch_raw_creds_list(client, base, headers)

    result_hosts = []
    seen_ips: set = set()

    for t in targets_by_id.values():
        host = _adaptix_target_to_host(t, agents_by_id)
        if host:
            result_hosts.append(host)
            seen_ips.add(host["ip"])

    for a in agents:
        if not a:
            continue
        host = _adaptix_agent_to_host(a, seen_ips)
        if host:
            result_hosts.append(host)
            seen_ips.add(host["ip"])

    result_creds = [c for item in raw_creds if (c := _adaptix_cred_result(item))]
    return {"hosts": result_hosts, "creds": result_creds}


def _astr(a: dict, key: str) -> str:
    return (a.get(key) or "").strip()


def _parse_adaptix_agent(a: dict, now_ts: int, stale_threshold: int) -> dict:
    mark = _astr(a, "a_mark")
    explicit_dead = mark.lower() in _ADAPTIX_DEAD_MARKS
    last_tick_raw = a.get("a_last_tick") or a.get("a_last_seen") or 0
    try:
        last_tick = int(last_tick_raw)
    except Exception:
        last_tick = 0
    stale = bool(last_tick > 1_000_000_000 and (now_ts - last_tick) > stale_threshold)
    alive = not (explicit_dead or stale)
    return {
        "ip": (_astr(a, "a_internal_ip") or _astr(a, "a_external_ip")),
        "hostname": _astr(a, "a_computer"),
        "username": _astr(a, "a_username"),
        "domain": _astr(a, "a_domain"),
        "os": _astr(a, "a_os_desc"),
        "arch": _astr(a, "a_arch"),
        "process": _astr(a, "a_process"),
        "agent_id": a.get("a_id") or "",
        "beacon_id": a.get("a_id") or "",
        "listener": a.get("a_listener") or "",
        "alive": alive,
        "mark": mark or ("stale" if stale else ""),
        "last_seen": a.get("a_last_seen") or "",
        "last_tick": last_tick if last_tick > 0 else None,
        "stale_seconds": (now_ts - last_tick) if (alive is False and stale) else None,
    }


async def _adaptix_live_agents(cfg: dict) -> list[dict]:
    url = cfg["url"].rstrip("/")
    ep = cfg.get("endpoint", _C2_ENDPOINT_PATH).rstrip("/") or _C2_ENDPOINT_PATH
    base = f"{url}{ep}"

    async with httpx.AsyncClient(verify=cfg.get("verify_ssl", False), timeout=30) as client:
        token = cfg.get("token", "")
        if not token:
            login_r = await client.post(
                f"{base}/login",
                json={"username": cfg.get("username") or "operator",
                      "password": cfg.get("password", ""), "version": ""},
            )
            login_r.raise_for_status()
            token = login_r.json().get("access_token") or ""

        headers = {"Authorization": f"Bearer {token}"}
        agents_r = await client.get(f"{base}/agent/list", headers=headers)
        agents_r.raise_for_status()
        agents = agents_r.json()
        if not isinstance(agents, list):
            agents = []

    import time as _time

    now_ts = int(_time.time())
    stale_threshold = int(cfg.get("stale_agent_seconds", 600))
    return [_parse_adaptix_agent(a, now_ts, stale_threshold) for a in agents]


async def _adaptix_auth_headers(cfg: dict, client: httpx.AsyncClient) -> dict[str, str]:
    token = cfg.get("token", "")
    if not token:
        login_r = await client.post(
            f"{cfg['_adaptix_base']}/login",
            json={
                "username": cfg.get("username") or "operator",
                "password": cfg.get("password", ""),
                "version": "",
            },
        )
        login_r.raise_for_status()
        token = login_r.json().get("access_token") or login_r.json().get("token") or ""
    return {"Authorization": f"Bearer {token}"}


def _adaptix_base(cfg: dict) -> str:
    url = cfg["url"].rstrip("/")
    ep = cfg.get("endpoint", _C2_ENDPOINT_PATH).rstrip("/") or _C2_ENDPOINT_PATH
    return f"{url}{ep}"


async def _adaptix_fetch_creds(cfg: dict) -> list[dict]:
    base = _adaptix_base(cfg)
    local_cfg = {**cfg, "_adaptix_base": base}
    async with httpx.AsyncClient(verify=cfg.get("verify_ssl", False), timeout=30) as client:
        headers = await _adaptix_auth_headers(local_cfg, client)
        c_r = await client.get(f"{base}/creds/list", headers=headers)
        c_r.raise_for_status()
        data = c_r.json()
        if not isinstance(data, list):
            return []
        return data


async def _adaptix_fetch_bof_catalog(cfg: dict) -> list[dict]:
    base = _adaptix_base(cfg)
    local_cfg = {**cfg, "_adaptix_base": base}
    async with httpx.AsyncClient(verify=cfg.get("verify_ssl", False), timeout=30) as client:
        headers = await _adaptix_auth_headers(local_cfg, client)
        r = await client.post(f"{base}/axscript/commands", headers=headers, json={})
        if r.status_code in (404, 405):
            return []
        r.raise_for_status()
        data = r.json()
        if not isinstance(data, list):
            return []
        return _normalize_axscript_catalog(data)


def _normalize_c2_cred(raw: dict, integration_id: str) -> dict:
    return {
        "id": raw.get("c_creds_id") or raw.get("id") or "",
        "source": "c2",
        "integration_id": integration_id,
        "username": (raw.get("c_username") or "").strip(),
        "secret": raw.get("c_password") or "",
        "domain": (raw.get("c_realm") or "").strip(),
        "host": (raw.get("c_host") or "").strip(),
        "type": (raw.get("c_type") or "plain").strip(),
        "label": (raw.get("c_username") or "").strip(),
    }


def _normalize_choice_list(raw) -> list[dict]:
    values = raw or []
    if isinstance(values, dict):
        values = values.get("choices") or values.get("options") or values.get("values") or []
    result = []
    for item in values:
        if isinstance(item, dict):
            value = item.get("value")
            if value is None:
                value = item.get("id") or item.get("name") or item.get("key")
            label = item.get("label") or item.get("title") or item.get("name") or str(value or "")
        else:
            value = item
            label = str(item)
        if value is None:
            continue
        result.append({"value": str(value), "label": str(label)})
    return result


def _normalize_param_type(raw_type: str, choices: list[dict]) -> str:
    t = (raw_type or "").strip().lower()
    if choices:
        return "choice"
    if t in ("bool", "boolean", "checkbox", "switch"):
        return "boolean"
    if t in ("int", "integer", "number", "float"):
        return "number"
    if t in ("select", "enum", "choice", "radio"):
        return "choice"
    if t in ("textarea", "multiline", "textblock"):
        return "textarea"
    return "text"


def _normalize_param(raw: dict, idx: int) -> dict:
    choices = _normalize_choice_list(
        raw.get("choices") or raw.get("options") or raw.get("enum") or raw.get("values")
    )
    key = (
        raw.get("key")
        or raw.get("name")
        or raw.get("id")
        or raw.get("param")
        or raw.get("arg")
        or f"arg_{idx + 1}"
    )
    label = raw.get("label") or raw.get("title") or raw.get("name") or key
    raw_type = (
        raw.get("type") or raw.get("input_type") or raw.get("kind") or raw.get("widget") or ""
    )
    return {
        "key": str(key),
        "label": str(label),
        "type": _normalize_param_type(str(raw_type), choices),
        "raw_type": str(raw_type),
        "required": bool(raw.get("required") or raw.get("mandatory")),
        "default": raw.get("default") if raw.get("default") is not None else raw.get("value"),
        "placeholder": raw.get("placeholder") or raw.get("example") or "",
        "description": raw.get("description") or raw.get("help") or raw.get("hint") or "",
        "choices": choices,
        "position": idx,
    }


def _extract_command_params(command: dict) -> list[dict]:
    raw_params = (
        command.get("parameters")
        or command.get("params")
        or command.get("args")
        or command.get("fields")
        or command.get("options")
        or []
    )
    if not isinstance(raw_params, list):
        return []
    return [
        _normalize_param(item if isinstance(item, dict) else {"name": str(item)}, idx)
        for idx, item in enumerate(raw_params)
    ]


def _build_template_from_command(name: str, command: dict, params: list[dict]) -> str:
    template = (
        command.get("template")
        or command.get("cmdline")
        or command.get("commandline")
        or command.get("usage")
        or ""
    )
    template = str(template or "").strip()
    if template:
        return template
    if not params:
        return name
    return " ".join([name, *[f"{{{{{param['key'].upper()}}}}}" for param in params]])


def _parse_template_placeholders(template: str, params: list[dict]) -> list[dict]:
    known = {item["key"] for item in params}
    next_params = list(params)
    for match in re.findall(r"\{\{([A-Z0-9_]+)\}\}", template or ""):
        key = match.lower()
        if key in known:
            continue
        next_params.append(
            {
                "key": key,
                "label": match,
                "type": "text",
                "raw_type": "placeholder",
                "required": False,
                "default": "",
                "placeholder": "",
                "description": "",
                "choices": [],
                "position": len(next_params),
            }
        )
        known.add(key)
    return next_params


def _axscript_command_entry(
    source_idx: int,
    group_idx: int,
    cmd_idx: int,
    command: dict,
    group_name: str,
    group_desc: str,
    script_name: str,
) -> dict | None:
    if not isinstance(command, dict):
        return None
    name = str(
        command.get("name") or command.get("cmd") or command.get("title") or command.get("command") or ""
    ).strip()
    if not name:
        return None
    params = _extract_command_params(command)
    template = _build_template_from_command(name, command, params)
    params = _parse_template_placeholders(template, params)
    return {
        "id": f"{source_idx}:{group_idx}:{cmd_idx}:{name}",
        "name": name,
        "title": command.get("title") or name,
        "group": group_name,
        "group_description": group_desc,
        "script_name": script_name,
        "description": command.get("description") or command.get("help") or group_desc,
        "template": template,
        "parameters": params,
        "raw": command,
    }


def _process_catalog_entry(source_idx: int, entry: dict, result: list) -> None:
    source_name = entry.get("Agent") or entry.get("agent_name") or entry.get("Listener") or ""
    groups = entry.get("Groups") or entry.get("groups") or []
    for group_idx, group in enumerate(groups):
        if not isinstance(group, dict):
            continue
        group_name = group.get("group_name") or group.get("name") or "General"
        group_desc = group.get("group_description") or group.get("description") or ""
        script_name = group.get("script_name") or group.get("source") or source_name or ""
        for cmd_idx, command in enumerate(group.get("commands") or []):
            entry_dict = _axscript_command_entry(
                source_idx, group_idx, cmd_idx, command, group_name, group_desc, script_name
            )
            if entry_dict:
                result.append(entry_dict)


def _normalize_axscript_catalog(raw_catalog: list[dict]) -> list[dict]:
    result = []
    for source_idx, entry in enumerate(raw_catalog or []):
        _process_catalog_entry(source_idx, entry, result)
    return result


async def _adaptix_fetch_agent_tasks(cfg: dict, agent_id: str, limit: int = 30) -> list[dict]:
    base = _adaptix_base(cfg)
    local_cfg = {**cfg, "_adaptix_base": base}
    async with httpx.AsyncClient(verify=cfg.get("verify_ssl", False), timeout=30) as client:
        headers = await _adaptix_auth_headers(local_cfg, client)
        task_r = await client.get(
            f"{base}/agent/task/list",
            headers=headers,
            params={"agent_id": agent_id, "limit": limit, "offset": 0},
        )
        task_r.raise_for_status()
        tasks = task_r.json()
        if not isinstance(tasks, list):
            return []
        return [
            {
                "task_id": item.get("a_task_id") or "",
                "cmdline": item.get("a_cmdline") or "",
                "completed": bool(item.get("a_completed")),
                "text": item.get("a_text") or "",
                "message": item.get("a_message") or "",
                "msg_type": item.get("a_msg_type") or "",
                "start_time": item.get("a_start_time") or "",
                "finish_time": item.get("a_finish_time") or "",
                "computer": item.get("a_computer") or "",
                "user": item.get("a_user") or "",
                "raw": item,
            }
            for item in tasks
        ]


def _find_completed_adaptix_task(tasks: list, commandline: str) -> tuple[bool, dict | None, dict]:
    latest = None
    for task in tasks:
        if (task.get("a_cmdline") or "").strip() != commandline.strip():
            continue
        latest = task
        if task.get("a_completed"):
            return True, task, {"task": task, "output": task.get("a_text") or task.get("a_message") or ""}
    return False, latest, {}


async def _adaptix_poll_output(
    client, base: str, headers: dict, agent_id: str, commandline: str, result: dict, timeout_seconds: int
) -> dict:
    started = utcnow()
    latest = None
    while (utcnow() - started).total_seconds() < max(3, timeout_seconds):
        task_r = await client.get(
            f"{base}/agent/task/list", headers=headers,
            params={"agent_id": agent_id, "limit": 20, "offset": 0},
        )
        tasks = task_r.json() if task_r.status_code == 200 else None
        if not isinstance(tasks, list):
            await asyncio.sleep(0.8)
            continue
        done, latest, updates = _find_completed_adaptix_task(tasks, commandline)
        if done:
            result.update(updates)
            return result
        await asyncio.sleep(0.8)
    if latest:
        result["task"] = latest
        result["output"] = latest.get("a_text") or latest.get("a_message") or ""
    return result


async def _adaptix_execute(
    cfg: dict,
    agent_id: str,
    commandline: str,
    wait_for_output: bool = True,
    timeout_seconds: int = 12,
) -> dict:
    base = _adaptix_base(cfg)
    local_cfg = {**cfg, "_adaptix_base": base}
    async with httpx.AsyncClient(
        verify=cfg.get("verify_ssl", False), timeout=max(30, timeout_seconds + 5)
    ) as client:
        headers = await _adaptix_auth_headers(local_cfg, client)
        exec_r = await client.post(
            f"{base}/agent/command/raw", headers=headers,
            json={"id": agent_id, "cmdline": commandline},
        )
        exec_r.raise_for_status()
        exec_data = exec_r.json() if exec_r.content else {"ok": True}
        result = {
            "accepted": bool(exec_data.get("ok", True)),
            "message": exec_data.get("message") or "",
            "commandline": commandline,
            "agent_id": agent_id,
        }
        if not wait_for_output:
            return result
        return await _adaptix_poll_output(client, base, headers, agent_id, commandline, result, timeout_seconds)
