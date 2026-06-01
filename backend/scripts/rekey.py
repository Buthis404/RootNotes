#!/usr/bin/env python3
"""
rekey.py — rotate the Fernet ENCRYPTION_KEY for all encrypted data in RootNotes.

Usage:
    OLD_KEY=<old_fernet_key> NEW_KEY=<new_fernet_key> python3 rekey.py [--dry-run]

Or pass keys as positional args:
    python3 rekey.py <old_key> <new_key> [--dry-run]

The script re-encrypts:
  - credentials.secret
  - notes.content  (only rows with __enc__: prefix)
  - loots.value    (only rows with __enc__: prefix)
  - loots files on disk (only rows with file_encrypted=True)
  - global_settings c2_integrations token/password fields

Run with --dry-run first to count affected rows without writing anything.

Requirements: run from the backend container or with all Python deps installed
and DATABASE_URL set (or DB_HOST/DB_PORT/DB_NAME/DB_USER/DB_PASSWORD env vars).
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
log = logging.getLogger(__name__)

_SENTINEL = "__enc__:"


def _build_dsn() -> str:
    if url := os.environ.get("DATABASE_URL", ""):
        return url
    host = os.environ.get("DB_HOST", "localhost")
    port = os.environ.get("DB_PORT", "5432")
    name = os.environ.get("DB_NAME", "rootnotes")
    user = os.environ.get("DB_USER", "rootnotes")
    pwd = os.environ.get("DB_PASSWORD", "")
    return f"postgresql://{user}:{pwd}@{host}:{port}/{name}"


def _make_fernet(key: str):
    from cryptography.fernet import Fernet
    try:
        return Fernet(key.encode() if isinstance(key, str) else key)
    except Exception as exc:
        log.error("Invalid Fernet key: %s", exc)
        sys.exit(1)


def _reencrypt_str(value: str, old_fernet, new_fernet) -> str | None:
    """Decrypt with old key, re-encrypt with new key. Returns None if not encrypted."""
    if not value or not value.startswith(_SENTINEL):
        return None
    try:
        plaintext = old_fernet.decrypt(value[len(_SENTINEL):].encode())
        new_cipher = new_fernet.encrypt(plaintext).decode()
        return f"{_SENTINEL}{new_cipher}"
    except Exception as exc:
        raise ValueError(f"Failed to decrypt value: {exc}") from exc


def _rekey_simple_column(conn, old_f, new_f, dry_run: bool, stats: dict,
                          select_sql: str, update_sql: str, stat_key: str, err_label: str) -> None:
    from sqlalchemy import text
    rows = conn.execute(text(select_sql), {"prefix": f"{_SENTINEL}%"}).fetchall()
    log.info("%s: %d encrypted rows found", stat_key, len(rows))
    for row_id, value in rows:
        try:
            new_val = _reencrypt_str(value, old_f, new_f)
            if new_val and not dry_run:
                conn.execute(text(update_sql), {"v": new_val, "id": row_id})
            stats[stat_key] += 1
        except Exception as exc:
            log.error("%s id=%s: %s", err_label, row_id, exc)
            stats["errors"] += 1


def _rekey_loot_files(conn, old_f, new_f, upload_root: Path, dry_run: bool, stats: dict) -> None:
    from sqlalchemy import text
    rows = conn.execute(text("SELECT id, storage_path FROM loots WHERE file_encrypted=TRUE")).fetchall()
    log.info("loots(files): %d encrypted file rows found", len(rows))
    for row_id, storage_path in rows:
        if not storage_path:
            continue
        path = upload_root / storage_path if not Path(storage_path).is_absolute() else Path(storage_path)
        if not path.exists():
            log.warning("loot id=%s: file not found at %s — skipping", row_id, path)
            continue
        try:
            plaintext = old_f.decrypt(path.read_bytes())
            if not dry_run:
                path.write_bytes(new_f.encrypt(plaintext))
            stats["loots_files"] += 1
        except Exception as exc:
            log.error("loot id=%s (file %s): %s", row_id, path, exc)
            stats["errors"] += 1


def _rekey_single_c2_integration(integration: dict, old_f, new_f, stats: dict) -> int:
    changed = 0
    for field in ("token", "password"):
        v = integration.get(field, "")
        if not v or not v.startswith(_SENTINEL):
            continue
        try:
            new_val = _reencrypt_str(v, old_f, new_f)
            if new_val:
                integration[field] = new_val
                changed += 1
        except Exception as exc:
            log.error("c2_integration field=%s: %s", field, exc)
            stats["errors"] += 1
    return changed


def _rekey_c2_integrations(conn, old_f, new_f, dry_run: bool, stats: dict) -> None:
    from sqlalchemy import text
    row = conn.execute(text("SELECT value FROM global_settings WHERE key='c2_integrations'")).fetchone()
    if not (row and row[0]):
        return
    integrations = row[0] if isinstance(row[0], list) else []
    changed = sum(_rekey_single_c2_integration(i, old_f, new_f, stats) for i in integrations)
    if changed:
        log.info("c2_integrations: %d encrypted fields re-keyed", changed)
        if not dry_run:
            conn.execute(
                text("UPDATE global_settings SET value=:v WHERE key='c2_integrations'"),
                {"v": json.dumps(integrations)},
            )
        stats["c2"] += changed


def rekey(old_key: str, new_key: str, dry_run: bool) -> None:
    from sqlalchemy import create_engine

    dsn = _build_dsn()
    engine = create_engine(dsn)
    old_f = _make_fernet(old_key)
    new_f = _make_fernet(new_key)
    upload_root = Path(os.environ.get("UPLOAD_ROOT", "/data/uploads"))
    stats = {"creds": 0, "notes": 0, "loots_value": 0, "loots_files": 0, "c2": 0, "errors": 0}

    with engine.begin() as conn:
        _rekey_simple_column(conn, old_f, new_f, dry_run, stats,
            "SELECT id, secret FROM credentials WHERE secret LIKE :prefix",
            "UPDATE credentials SET secret=:v WHERE id=:id", "creds", "cred")
        _rekey_simple_column(conn, old_f, new_f, dry_run, stats,
            "SELECT id, content FROM notes WHERE content LIKE :prefix",
            "UPDATE notes SET content=:v WHERE id=:id", "notes", "note")
        _rekey_simple_column(conn, old_f, new_f, dry_run, stats,
            "SELECT id, value FROM loots WHERE value LIKE :prefix",
            "UPDATE loots SET value=:v WHERE id=:id", "loots_value", "loot")
        _rekey_loot_files(conn, old_f, new_f, upload_root, dry_run, stats)
        _rekey_c2_integrations(conn, old_f, new_f, dry_run, stats)

    mode = "[DRY RUN] " if dry_run else ""
    log.info(
        "%sRe-key complete: creds=%d notes=%d loots_value=%d loots_files=%d c2_fields=%d errors=%d",
        mode, stats["creds"], stats["notes"], stats["loots_value"],
        stats["loots_files"], stats["c2"], stats["errors"],
    )
    if stats["errors"]:
        log.error("Re-key finished with %d errors — review output above before switching keys", stats["errors"])
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Rotate RootNotes ENCRYPTION_KEY")
    parser.add_argument("old_key", nargs="?", help="Old Fernet key (or set OLD_KEY env var)")
    parser.add_argument("new_key", nargs="?", help="New Fernet key (or set NEW_KEY env var)")
    parser.add_argument("--dry-run", action="store_true", help="Count affected rows without writing")
    args = parser.parse_args()

    old_key = args.old_key or os.environ.get("OLD_KEY", "")
    new_key = args.new_key or os.environ.get("NEW_KEY", "")

    if not old_key or not new_key:
        parser.error("Both old_key and new_key are required (positional args or OLD_KEY/NEW_KEY env vars)")

    if old_key == new_key:
        log.error("OLD_KEY and NEW_KEY are identical — nothing to do")
        sys.exit(1)

    if args.dry_run:
        log.info("=== DRY RUN — no data will be modified ===")

    rekey(old_key, new_key, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
