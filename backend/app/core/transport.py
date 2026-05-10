"""
Unified transport abstractions: CancellationToken and RunResult.

CancellationToken — thread-safe flag usable from asyncio coroutines and
executor threads alike. WorkerPool creates one per job; cancel_job() sets it;
SSH and other blocking calls poll or watch it to exit early.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Literal


@dataclass
class RunResult:
    status: Literal["done", "failed", "cancelled"] = "failed"
    output: str = ""
    error: str = ""
    result: dict = field(default_factory=dict)


class CancellationToken:
    """Thread-safe cancellation flag.

    cancel()        — set the flag (idempotent)
    is_cancelled    — property: True once set
    wait(timeout)   — block up to `timeout` seconds; returns True if cancelled
    """

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def is_cancelled(self) -> bool:
        return self._event.is_set()

    def wait(self, timeout: float) -> bool:
        """Block until cancelled or timeout. Returns True if cancelled."""
        return self._event.wait(timeout=timeout)
