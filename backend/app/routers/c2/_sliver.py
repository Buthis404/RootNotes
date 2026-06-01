import asyncio

from fastapi import HTTPException

from ...core.logging_setup import get_logger

logger = get_logger(__name__)

_SLIVER_MIN_COMPAT = (1, 0, 0)
_SLIVER_MAX_COMPAT = (1, 6, 99)


def _sliver_parse_config(cfg: dict):
    from sliver import SliverClientConfig

    blob = (cfg.get("token") or "").strip()
    if not blob:
        raise HTTPException(400, "Sliver operator config (JSON) is empty")
    try:
        return SliverClientConfig.parse_config(blob)
    except Exception as e:
        raise HTTPException(400, f"Invalid Sliver operator config: {e}")


async def _sliver_connect(cfg: dict):
    from sliver import SliverClient

    config = _sliver_parse_config(cfg)
    client = SliverClient(config)
    await client.connect()

    try:
        ver = await client.version()
        major = getattr(ver, "Major", 0) or 0
        minor = getattr(ver, "Minor", 0) or 0
        patch = getattr(ver, "Patch", 0) or 0
        server_ver = (int(major), int(minor), int(patch))
        if server_ver > _SLIVER_MAX_COMPAT:
            logger.warning(
                "Sliver server v%d.%d.%d detected; sliver-py 0.0.19 was built for "
                "≤1.6.x protos. Some RPC calls (execute, implant management) may "
                "fail with NOT_FOUND. See B10-17 in BACKLOG2.md.",
                *server_ver,
            )
    except Exception as e:
        logger.debug("Sliver server version check failed: %s", e)

    return client


def _sliver_raise_compat(exc: Exception, operation: str) -> None:
    exc_str = str(exc).lower()
    if "not_found" in exc_str or "statuscode.not_found" in exc_str or "404" in exc_str:
        raise HTTPException(
            502,
            f"Sliver {operation} returned NOT_FOUND. "
            "This usually means the Sliver server version (≥1.7.x) is incompatible "
            "with sliver-py 0.0.19. Check the server logs and see B10-17 in BACKLOG2.md.",
        ) from exc
    raise HTTPException(502, f"Sliver {operation} error: {exc}") from exc


def _sliver_format_host(item, is_beacon: bool) -> dict:
    remote = getattr(item, "RemoteAddress", "") or ""
    ip = remote.split(":")[0] if remote else ""
    if not ip:
        ip = getattr(item, "ActiveC2", "") or ""
    os_str = getattr(item, "OS", "") or ""
    arch = getattr(item, "Arch", "") or ""
    return {
        "ip": ip,
        "hostname": getattr(item, "Hostname", "") or "",
        "os": (os_str + (" " + arch if arch else "")).strip(),
        "username": getattr(item, "Username", "") or "",
        "arch": arch,
        "process": getattr(item, "Filename", "") or "",
        "pid": getattr(item, "PID", None),
        "alive": not getattr(item, "IsDead", False),
        "beacon_id": getattr(item, "ID", "") or "",
        "note": ("Beacon: " if is_beacon else "Session: ") + (getattr(item, "Name", "") or ""),
        "source": "sliver",
        "domain": "",
    }


async def _sliver_sync(cfg: dict) -> dict:
    client = await _sliver_connect(cfg)
    try:
        sessions = await client.sessions()
        beacons = await client.beacons()
    finally:
        await client.close()
    hosts = [_sliver_format_host(s, is_beacon=False) for s in (sessions or [])] + [
        _sliver_format_host(b, is_beacon=True) for b in (beacons or [])
    ]
    return {"hosts": hosts, "creds": []}


async def _sliver_exec_session(
    interact, program: str, args: list, wait_for_output: bool, timeout_seconds: int,
    agent_id: str, commandline: str
) -> dict:
    try:
        exec_result = await asyncio.wait_for(
            interact.execute(program, args, output=wait_for_output),
            timeout=max(5, timeout_seconds),
        )
    except Exception as e:
        _sliver_raise_compat(e, "session execute")
    output = ""
    if exec_result is not None:
        stdout = getattr(exec_result, "Stdout", b"") or b""
        stderr = getattr(exec_result, "Stderr", b"") or b""
        output = stdout.decode(errors="replace") if isinstance(stdout, (bytes, bytearray)) else stdout
        if stderr:
            err = stderr.decode(errors="replace") if isinstance(stderr, (bytes, bytearray)) else stderr
            output = f"{output}\n[stderr]\n{err}" if output else err
    return {
        "accepted": True, "agent_id": agent_id, "commandline": commandline, "kind": "session",
        "output": output,
        "status": getattr(exec_result, "Status", 0) if exec_result else 0,
    }


def _sliver_format_live(item, is_beacon: bool) -> dict:
    alive = not getattr(item, "IsDead", False)
    remote = getattr(item, "RemoteAddress", "") or ""
    last_checkin = getattr(item, "LastCheckin", None)
    return {
        "ip": remote.split(":")[0] if remote else "",
        "hostname": getattr(item, "Hostname", "") or "",
        "username": getattr(item, "Username", "") or "",
        "domain": "",
        "os": (getattr(item, "OS", "") or "")
        + (" " + getattr(item, "Arch", "") if getattr(item, "Arch", "") else ""),
        "arch": getattr(item, "Arch", "") or "",
        "process": getattr(item, "Filename", "") or "",
        "beacon_id": getattr(item, "ID", "") or "",
        "listener": getattr(item, "ActiveC2", "") or "",
        "alive": alive,
        "mark": "alive" if alive else "dead",
        "last_seen": str(last_checkin) if last_checkin else "",
        "session_type": "beacon" if is_beacon else "session",
    }


async def _sliver_live_agents(cfg: dict) -> list[dict]:
    client = await _sliver_connect(cfg)
    try:
        sessions = await client.sessions()
        beacons = await client.beacons()
    finally:
        await client.close()
    return [_sliver_format_live(s, is_beacon=False) for s in (sessions or [])] + [
        _sliver_format_live(b, is_beacon=True) for b in (beacons or [])
    ]


async def _sliver_execute(
    cfg: dict,
    agent_id: str,
    commandline: str,
    wait_for_output: bool = True,
    timeout_seconds: int = 12,
) -> dict:
    import shlex

    try:
        parts = shlex.split(commandline)
    except ValueError as e:
        raise HTTPException(400, f"Sliver execute: malformed command line: {e}")
    if not parts:
        raise HTTPException(400, "Sliver execute: empty command")
    program, args = parts[0], parts[1:]

    client = await _sliver_connect(cfg)
    try:
        sessions = await client.sessions()
        target_session = next(
            (s for s in (sessions or []) if getattr(s, "ID", "") == agent_id), None
        )
        if target_session:
            interact = await client.interact_session(agent_id)
            if interact is None:
                raise HTTPException(404, f"Sliver session {agent_id!r} not found (interact returned None)")
            return await _sliver_exec_session(interact, program, args, wait_for_output, timeout_seconds, agent_id, commandline)

        beacons = await client.beacons()
        target_beacon = next((b for b in (beacons or []) if getattr(b, "ID", "") == agent_id), None)
        if not target_beacon:
            raise HTTPException(404, f"Sliver agent {agent_id!r} not found")
        interact = await client.interact_beacon(agent_id)
        if interact is None:
            raise HTTPException(
                404, f"Sliver beacon {agent_id!r} not found (interact returned None)"
            )
        try:
            task = await interact.execute(program, args, output=wait_for_output)
        except Exception as e:
            _sliver_raise_compat(e, "beacon execute")
        task_id = getattr(task, "ID", "") if task else ""
        return {
            "accepted": True,
            "agent_id": agent_id,
            "commandline": commandline,
            "kind": "beacon",
            "task_id": task_id,
            "output": "",
        }
    finally:
        await client.close()


async def _sliver_fetch_agent_tasks(cfg: dict, agent_id: str, limit: int = 30) -> list[dict]:
    client = await _sliver_connect(cfg)
    try:
        beacons = await client.beacons()
        target_beacon = next((b for b in (beacons or []) if getattr(b, "ID", "") == agent_id), None)
        if not target_beacon:
            return []
        interact = await client.interact_beacon(agent_id)
        if interact is None:
            return []
        try:
            tasks = await interact.tasks()
        except Exception as e:
            logger.warning("Sliver beacon tasks fetch failed for %s: %s", agent_id, e)
            return []
    finally:
        await client.close()

    result = []
    for t in (tasks or [])[:limit]:
        description = getattr(t, "Description", "") or ""
        state = getattr(t, "State", "") or ""
        result.append(
            {
                "task_id": getattr(t, "ID", "") or "",
                "cmdline": description,
                "completed": state.lower() == "completed",
                "text": "",
                "message": "",
                "msg_type": state,
                "start_time": str(getattr(t, "CreatedAt", "") or ""),
                "finish_time": str(getattr(t, "CompletedAt", "") or ""),
                "computer": "",
                "user": "",
                "raw": {"id": getattr(t, "ID", ""), "state": state, "description": description},
            }
        )
    return result
