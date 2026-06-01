"""
arq Redis pool singleton — used by the API process to enqueue jobs.

Initialized in main.py lifespan when WORKER_BACKEND=arq is set.
Import get_arq_pool() anywhere; returns None if arq mode is not active.
"""

from __future__ import annotations

try:
    from arq import ArqRedis

    _ArqRedis = ArqRedis
except ImportError:
    _ArqRedis = object  # type: ignore

_pool: object | None = None  # ArqRedis at runtime


def set_arq_pool(pool) -> None:
    global _pool
    _pool = pool


def get_arq_pool():
    """Return the active ArqRedis pool, or None if arq mode is disabled."""
    return _pool
