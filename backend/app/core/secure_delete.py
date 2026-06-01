"""Secure file deletion helpers (B10-24).

Plain unlink() leaves file content recoverable via forensic disk analysis.
For attacker-boxes with NTDS dumps, loot archives and uploaded artifacts
this is a meaningful operational risk.

When SECURE_DELETE=true, deletion attempts:
  1. shred -uzn 3 <path>  (GNU coreutils, overwrites 3 passes + zeros + unlinks)
  2. Fallback: single-pass zero-overwrite + unlink (if shred absent)
  3. Final fallback: plain unlink (logs a warning)

When SECURE_DELETE is unset or false (default), plain unlink is used — same
behaviour as before B10-24.

Directory removal (secure_delete_tree) walks files depth-first, secure-deletes
each file, then rmdir's the empty directories.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

_SECURE = os.environ.get("SECURE_DELETE", "false").strip().lower() in ("1", "true", "yes")


def _shred(path: Path) -> bool:
    """Return True if shred succeeded."""
    try:
        result = subprocess.run(
            ["shred", "-uzn", "3", str(path)],
            capture_output=True,
            timeout=30,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _overwrite_and_unlink(path: Path) -> None:
    """Single-pass zero overwrite then unlink. Best-effort."""
    try:
        size = path.stat().st_size
        with open(path, "r+b") as fh:
            fh.write(b"\x00" * size)
            fh.flush()
            os.fsync(fh.fileno())
    except Exception as exc:
        logger.warning("secure_delete: overwrite failed for %s: %s", path, exc)
    path.unlink(missing_ok=True)


def secure_delete_file(path: Path | str) -> None:
    """Delete a single file, securely if SECURE_DELETE=true."""
    path = Path(path)
    if not path.exists():
        return
    if not _SECURE:
        path.unlink(missing_ok=True)
        return
    if _shred(path):
        return
    logger.warning(
        "secure_delete: shred not available, falling back to overwrite+unlink for %s", path
    )
    _overwrite_and_unlink(path)


def secure_delete_tree(directory: Path | str) -> None:
    """Recursively delete a directory, secure-deleting each file first."""
    directory = Path(directory)
    if not directory.exists():
        return
    if not _SECURE:
        shutil.rmtree(directory, ignore_errors=True)
        return
    # Walk depth-first: delete files, then remove empty dirs
    for root, dirs, files in os.walk(directory, topdown=False):
        root_path = Path(root)
        for fname in files:
            secure_delete_file(root_path / fname)
        for dname in dirs:
            try:
                (root_path / dname).rmdir()
            except OSError:
                pass
    try:
        directory.rmdir()
    except OSError:
        # Non-empty means some delete failed; log and rmtree as fallback
        logger.warning(
            "secure_delete: directory not empty after secure walk, falling back to rmtree: %s",
            directory,
        )
        shutil.rmtree(directory, ignore_errors=True)
