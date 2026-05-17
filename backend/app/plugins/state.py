import re

from sqlalchemy.orm import Session

from .. import models
from ..database import SessionLocal
from ..core.crypto import encrypt_str, decrypt_str
from .registry import registry
from .types import BackendModule


MODULE_STATE_KEY = "module_state"
ATTACKER_SSH_KEY = "attacker_ssh_config"
MODULE_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]{2,64}$")


def _default_module_state() -> dict:
    return {"states": {}, "custom_modules": []}


def _default_attacker_config() -> dict:
    return {
        "targets": [],
    }


def _get_setting(db: Session, key: str, default):
    item = db.query(models.GlobalSetting).filter(models.GlobalSetting.key == key).first()
    if not item:
        item = models.GlobalSetting(key=key, value=default)
        db.add(item)
        db.commit()
        db.refresh(item)
    return item


def load_module_state(db: Session | None = None) -> dict:
    owns_db = db is None
    db = db or SessionLocal()
    try:
        item = _get_setting(db, MODULE_STATE_KEY, _default_module_state())
        value = item.value if isinstance(item.value, dict) else _default_module_state()
        value.setdefault("states", {})
        value.setdefault("custom_modules", [])
        return value
    finally:
        if owns_db:
            db.close()


def save_module_state(state: dict, db: Session | None = None):
    owns_db = db is None
    db = db or SessionLocal()
    try:
        item = _get_setting(db, MODULE_STATE_KEY, _default_module_state())
        item.value = state
        db.commit()
    finally:
        if owns_db:
            db.close()


def load_attacker_ssh_config(db: Session | None = None) -> dict:
    owns_db = db is None
    db = db or SessionLocal()
    try:
        item = _get_setting(db, ATTACKER_SSH_KEY, _default_attacker_config())
        value = item.value if isinstance(item.value, dict) else _default_attacker_config()
        merged = {**_default_attacker_config(), **value}
        legacy_host = value.get("host") if isinstance(value, dict) else None
        if legacy_host and not merged.get("targets"):
            merged["targets"] = [{
                "id": "legacy-global",
                "name": "Legacy Global SSH",
                "host": value.get("host", ""),
                "port": value.get("port", 22),
                "username": value.get("username", ""),
                "password": value.get("password", ""),
                "private_key": value.get("private_key", ""),
                "known_hosts_policy": value.get("known_hosts_policy", "accept_new"),
                "project_ids": [],
                "enabled": True,
            }]
        return merged
    finally:
        if owns_db:
            db.close()


def save_attacker_ssh_config(config: dict, db: Session | None = None) -> dict:
    owns_db = db is None
    db = db or SessionLocal()
    try:
        item = _get_setting(db, ATTACKER_SSH_KEY, _default_attacker_config())
        merged = {**_default_attacker_config(), **config}
        item.value = merged
        db.commit()
        return merged
    finally:
        if owns_db:
            db.close()


def _decrypt_target(target: dict) -> dict:
    """Return a copy of target with password/private_key decrypted.

    Also fills role flags (`is_operator`, `runs_pivot`) with True defaults
    for targets created before these fields existed — preserves prior
    behaviour where every target could both exec and host pivots.
    """
    t = dict(target)
    t["password"] = decrypt_str(t.get("password", ""))
    t["private_key"] = decrypt_str(t.get("private_key", ""))
    t["proxy_password"] = decrypt_str(t.get("proxy_password", ""))
    t["proxy_private_key"] = decrypt_str(t.get("proxy_private_key", ""))
    t["exec_proxy_password"] = decrypt_str(t.get("exec_proxy_password", ""))
    t.setdefault("is_operator", True)
    t.setdefault("runs_pivot", True)
    return t


def list_attacker_targets_for_exec(db: Session | None = None) -> list[dict]:
    """Subset of enabled targets that can be used for scans / playbook exec."""
    return [t for t in list_attacker_targets(db)
            if t.get("enabled", True) and t.get("is_operator", True)]


def list_attacker_targets_for_pivot(db: Session | None = None) -> list[dict]:
    """Subset of enabled targets that run chisel/ligolo (or were configured
    to host pivot routes)."""
    return [t for t in list_attacker_targets(db)
            if t.get("enabled", True) and t.get("runs_pivot", True)]


def _encrypt_target(target: dict) -> dict:
    """Return a copy of target with password/private_key encrypted."""
    t = dict(target)
    t["password"] = encrypt_str(t.get("password", ""))
    t["private_key"] = encrypt_str(t.get("private_key", ""))
    t["proxy_password"] = encrypt_str(t.get("proxy_password", ""))
    t["proxy_private_key"] = encrypt_str(t.get("proxy_private_key", ""))
    t["exec_proxy_password"] = encrypt_str(t.get("exec_proxy_password", ""))
    return t


def list_attacker_targets(db: Session | None = None) -> list[dict]:
    config = load_attacker_ssh_config(db)
    return [_decrypt_target(t) for t in config.get("targets", [])]


def list_attacker_targets_safe(db: Session | None = None) -> list[dict]:
    targets = list_attacker_targets(db)
    safe = []
    for target in targets:
        item = dict(target)
        has_password = bool(item.get("password"))
        has_private_key = bool(item.get("private_key"))
        has_proxy_password = bool(item.get("proxy_password"))
        has_proxy_private_key = bool(item.get("proxy_private_key"))
        has_exec_proxy_password = bool(item.get("exec_proxy_password"))
        item["password"] = ""
        item["private_key"] = ""
        item["proxy_password"] = ""
        item["proxy_private_key"] = ""
        item["exec_proxy_password"] = ""
        item["has_password"] = has_password
        item["has_private_key"] = has_private_key
        item["has_proxy_password"] = has_proxy_password
        item["has_proxy_private_key"] = has_proxy_private_key
        item["has_exec_proxy_password"] = has_exec_proxy_password
        safe.append(item)
    return safe


def save_attacker_targets(targets: list[dict], db: Session | None = None) -> list[dict]:
    config = load_attacker_ssh_config(db)
    config["targets"] = [_encrypt_target(t) for t in targets]
    saved = save_attacker_ssh_config(config, db).get("targets", [])
    return [_decrypt_target(t) for t in saved]


def apply_saved_state():
    state = load_module_state()

    for item in state.get("custom_modules", []):
        name = item.get("name", "")
        if not name:
            continue
        registry.register(BackendModule(
            name=name,
            title=item.get("title") or name,
            version=item.get("version") or "1.0.0",
            description=item.get("description") or "",
            enabled=bool(item.get("enabled", True)),
            source="custom",
            editable=True,
        ))

    for name, module_state in state.get("states", {}).items():
        module = registry.get(name)
        if not module:
            continue
        if "enabled" in module_state:
            module.enabled = bool(module_state["enabled"])
        if module_state.get("title"):
            module.title = module_state["title"]
        if module_state.get("version"):
            module.version = module_state["version"]
        if module_state.get("description") is not None:
            module.description = module_state["description"]


def list_modules() -> list[dict]:
    return [m.to_dict() for m in sorted(registry.get_all(), key=lambda mod: (mod.source != "builtin", (mod.title or mod.name).lower()))]


def create_custom_module(name: str, title: str, version: str, description: str, enabled: bool = True) -> dict:
    if registry.get(name):
        raise ValueError("Module already exists")

    state = load_module_state()
    state["custom_modules"].append({
        "name": name,
        "title": title or name,
        "version": version or "1.0.0",
        "description": description or "",
        "enabled": bool(enabled),
    })
    save_module_state(state)

    module = BackendModule(
        name=name,
        title=title or name,
        version=version or "1.0.0",
        description=description or "",
        enabled=bool(enabled),
        source="custom",
        editable=True,
    )
    registry.register(module)
    return module.to_dict()


def update_module(name: str, *, enabled=None, title=None, version=None, description=None) -> dict | None:
    module = registry.get(name)
    if not module:
        return None

    state = load_module_state()
    module_state = state.setdefault("states", {}).setdefault(name, {})
    if enabled is not None:
        module.enabled = bool(enabled)
        module_state["enabled"] = bool(enabled)
    if title is not None:
        module.title = title.strip() or module.name
        module_state["title"] = module.title
    if version is not None:
        module.version = version.strip() or module.version
        module_state["version"] = module.version
    if description is not None:
        module.description = description.strip()
        module_state["description"] = module.description

    if module.source == "custom":
        for item in state.get("custom_modules", []):
            if item.get("name") != name:
                continue
            item["title"] = module.title
            item["version"] = module.version
            item["description"] = module.description
            if enabled is not None:
                item["enabled"] = bool(enabled)
            break

    save_module_state(state)
    return module.to_dict()


def delete_custom_module(name: str) -> bool:
    module = registry.get(name)
    if not module or module.source != "custom":
        return False

    state = load_module_state()
    before = len(state.get("custom_modules", []))
    state["custom_modules"] = [item for item in state.get("custom_modules", []) if item.get("name") != name]
    state.get("states", {}).pop(name, None)
    save_module_state(state)
    registry._modules.pop(name, None)
    return len(state["custom_modules"]) != before


def delete_uploaded_module(name: str) -> bool:
    from pathlib import Path

    module = registry.get(name)
    if not module or module.source != "uploaded":
        return False

    module_path = Path(__file__).parent / "modules" / f"{name}.py"
    if not module_path.exists():
        return False

    module_path.unlink()
    state = load_module_state()
    state.get("states", {}).pop(name, None)
    save_module_state(state)
    registry._modules.pop(name, None)
    return True
