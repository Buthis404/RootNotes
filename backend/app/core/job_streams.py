"""
In-memory line buffer for live job output streaming.
One buffer per active job; cleaned up after job completes + TTL.
"""

import threading
import time

_buffers: dict[str, dict] = {}
_lock = threading.Lock()
_TTL = 300  # keep buffer 5 min after close


def init_stream(job_id: str) -> None:
    with _lock:
        _buffers[job_id] = {"lines": [], "closed": False, "closed_at": None}


def push_line(job_id: str, line: str) -> None:
    with _lock:
        buf = _buffers.get(job_id)
        if buf and not buf["closed"]:
            buf["lines"].append(line)


def get_lines(job_id: str, from_idx: int = 0) -> list[str]:
    with _lock:
        buf = _buffers.get(job_id)
        if not buf:
            return []
        return buf["lines"][from_idx:]


def is_closed(job_id: str) -> bool:
    with _lock:
        buf = _buffers.get(job_id)
        return buf is None or buf["closed"]


def close_stream(job_id: str) -> None:
    with _lock:
        buf = _buffers.get(job_id)
        if buf:
            buf["closed"] = True
            buf["closed_at"] = time.monotonic()


def cleanup_expired() -> None:
    now = time.monotonic()
    with _lock:
        expired = [
            jid
            for jid, buf in _buffers.items()
            if buf["closed"] and buf["closed_at"] and (now - buf["closed_at"]) > _TTL
        ]
        for jid in expired:
            del _buffers[jid]
