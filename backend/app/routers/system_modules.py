import ast
import traceback
from pathlib import Path

from fastapi import APIRouter, Depends, File, Header, HTTPException, UploadFile
from typing import Annotated
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from .. import models
from ..core.deps import require_admin
from ..core.plugin_signing import require_signature, sign_content, signing_enabled, verify_signature
from ..core.ssh_exec import run_ssh_command
from ..core.utils import new_id, ts_now
from ..plugins.loader import load_plugin_module
from ..plugins.registry import registry
from ..plugins.state import (
    MODULE_NAME_RE,
    create_custom_module,
    delete_custom_module,
    delete_uploaded_module,
    list_attacker_targets,
    list_attacker_targets_safe,
    list_modules,
    save_attacker_targets,
    update_module,
)

router = APIRouter(
    prefix="/api/admin/modules", tags=["system-modules"],
    responses={
        400: {"description": "Bad request"},
        404: {"description": "Not found"},
        409: {"description": "Conflict"},
    },
)

_MSG_ATTACKER_NOT_FOUND = "Attacker target not found"

MODULES_DIR = Path(__file__).resolve().parent.parent / "plugins" / "modules"
MODULE_TEMPLATE = '''from ..types import BackendModule


def sample_parser(content: str) -> list[dict]:
    """Replace with your real parser or hooks."""
    return []


MODULE = BackendModule(
    name="my_module",
    title="My Module",
    version="1.0.0",
    description="Short description of what this module does.",
    enabled=True,
    source="uploaded",
    editable=True,
    scan_parsers={"sample": sample_parser},
)
'''

FRONTEND_MODULE_TEMPLATE = """import { moduleRegistry } from '../registry.js';

moduleRegistry.register({
  id: 'my-module',
  title: 'My Module',
  version: '1.0.0',
  description: 'Frontend companion for My Module',
  enabled: true,
  menuItems: [],
  projectTabs: [],
  hostTabs: [],
  networkTabs: [],
  reportSections: [],
  importers: [],
  dashboardWidgets: [],
  actions: { hosts: [], findings: [], creds: [], networkNodes: [] },
});
"""


class CreateModuleBody(BaseModel):
    name: str
    title: str
    version: str = "1.0.0"
    description: str = ""
    enabled: bool = True


class UpdateModuleBody(BaseModel):
    enabled: bool | None = None
    title: str | None = None
    version: str | None = None
    description: str | None = None


class ValidateModuleBody(BaseModel):
    filename: str
    content: str


class AttackerSSHTargetBody(BaseModel):
    name: str
    host: str
    port: int = 22
    username: str
    password: str = ""
    private_key: str = ""
    known_hosts_policy: str = "accept_new"
    proxy_type: str = "none"
    proxy_host: str = ""
    proxy_port: int = 1080
    proxy_username: str = ""
    proxy_password: str = ""
    proxy_private_key: str = ""
    exec_proxy_type: str = "none"
    exec_proxy_host: str = ""
    exec_proxy_port: int = 1080
    exec_proxy_username: str = ""
    exec_proxy_password: str = ""
    exec_jump_host: str = ""
    exec_jump_port: int = 22
    exec_jump_username: str = ""
    project_ids: list[str] = []
    enabled: bool = True
    # Role flags — both default True for backwards compatibility with
    # targets stored before these fields existed.
    is_operator: bool = True  # can run scans / bulk exec / playbooks
    runs_pivot: bool = True  # chisel / ligolo runs here → pivot collector polls it


class AttackerSSHExecuteBody(BaseModel):
    command: str
    timeout_seconds: int = 30


def _require_attacker_module_enabled():
    module = registry.get("attacker_ssh")
    if not module or not module.enabled:
        raise HTTPException(404, "Attacker SSH module is disabled")


# Imports that raise a warning (useful in scan/pentest code, but flagged for awareness)
_SENSITIVE_IMPORTS = {"subprocess", "socket", "ctypes", "multiprocessing"}

# Calls that are hard errors — executing arbitrary code undermines any sandbox
_BLOCKED_CALLS = {"eval", "exec", "__import__", "compile"}


def _check_ast_import_node(node) -> list[str]:
    names = (
        [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
    )
    return [
        f"Import of potentially sensitive module: {name!r}"
        for name in names
        if name.split(".")[0] in _SENSITIVE_IMPORTS
    ]


def _check_ast_call_node(node: ast.Call) -> str | None:
    func = node.func
    call_name = ""
    if isinstance(func, ast.Name):
        call_name = func.id
    elif isinstance(func, ast.Attribute):
        call_name = f"{getattr(func.value, 'id', '')}.{func.attr}"
    matched = (
        call_name
        if call_name in _BLOCKED_CALLS
        else next((d for d in _BLOCKED_CALLS if call_name.endswith(f".{d}")), None)
    )
    if matched:
        return f"Forbidden call: {call_name!r} — dynamic code execution is not permitted in plugin modules"
    return None


def _scan_ast_tree(tree) -> tuple[list[str], list[str]]:
    warnings: list[str] = []
    errors: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            warnings.extend(_check_ast_import_node(node))
        elif isinstance(node, ast.Call):
            err = _check_ast_call_node(node)
            if err:
                errors.append(err)
    return warnings, errors


def _validate_module_source(filename: str, content: str) -> tuple[str, list[str]]:
    if not filename.endswith(".py"):
        raise HTTPException(400, "Only .py module files are supported")
    module_name = Path(filename).stem
    if not MODULE_NAME_RE.match(module_name):
        raise HTTPException(400, "Invalid module filename")
    if not content.strip():
        raise HTTPException(400, "Uploaded module is empty")
    try:
        tree = ast.parse(content, filename=filename)
    except SyntaxError as e:
        raise HTTPException(400, f"Syntax error in module (line {e.lineno}): {e.msg}")
    warnings, errors = _scan_ast_tree(tree)
    if errors:
        raise HTTPException(400, f"Module rejected: {'; '.join(errors)}")
    if "MODULE = BackendModule(" not in content:
        warnings.append("Template marker `MODULE = BackendModule(...)` was not found")
    if "from ..types import BackendModule" not in content:
        warnings.append("Expected import `from ..types import BackendModule` was not found")
    return module_name, warnings


@router.get("", responses={400: {"description": "Bad request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}, 409: {"description": "Conflict"}})
def admin_list_modules(admin: Annotated[models.User, Depends(require_admin)]):
    return {"modules": list_modules()}


@router.get("/template", responses={400: {"description": "Bad request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}, 409: {"description": "Conflict"}})
def admin_module_template(admin: Annotated[models.User, Depends(require_admin)]):
    return PlainTextResponse(
        MODULE_TEMPLATE,
        headers={"Content-Disposition": 'attachment; filename="module_template.py"'},
        media_type="text/x-python",
    )


@router.get("/template/frontend", responses={400: {"description": "Bad request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}, 409: {"description": "Conflict"}})
def admin_frontend_module_template(admin: Annotated[models.User, Depends(require_admin)]):
    return PlainTextResponse(
        FRONTEND_MODULE_TEMPLATE,
        headers={"Content-Disposition": 'attachment; filename="frontend_module_template.js"'},
        media_type="application/javascript",
    )


@router.post("/validate", responses={400: {"description": "Bad request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}, 409: {"description": "Conflict"}})
def admin_validate_module(body: ValidateModuleBody, admin: Annotated[models.User, Depends(require_admin)]):
    module_name, warnings = _validate_module_source(body.filename, body.content)
    return {"ok": True, "module_name": module_name, "warnings": warnings}


@router.post("/sign", responses={400: {"description": "Bad request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}, 409: {"description": "Conflict"}})
def admin_sign_module(body: ValidateModuleBody, admin: Annotated[models.User, Depends(require_admin)]):
    """Return an HMAC-SHA256 signature for a module file.

    Requires PLUGIN_SIGNING_KEY to be set.  The returned signature must be
    passed as the X-Plugin-Signature header when uploading the module while
    PLUGIN_REQUIRE_SIGNATURE=true.
    """
    if not signing_enabled():
        raise HTTPException(
            400, "PLUGIN_SIGNING_KEY is not configured — module signing is disabled"
        )
    _validate_module_source(body.filename, body.content)
    sig = sign_content(body.content.encode())
    return {"filename": body.filename, "signature": sig}


def _validate_main_proxy(body: "AttackerSSHTargetBody") -> None:
    if body.proxy_type not in {"none", "jump", "socks5"}:
        raise HTTPException(400, "Invalid proxy_type")
    if body.proxy_type == "none":
        return
    if not body.proxy_host.strip():
        raise HTTPException(400, "Proxy host is required when proxy_type is enabled")
    if body.proxy_port <= 0 or body.proxy_port > 65535:
        raise HTTPException(400, "Invalid proxy port")
    if body.proxy_type == "jump" and not body.proxy_username.strip():
        raise HTTPException(400, "Proxy username is required for jump host mode")
    if body.proxy_type == "jump" and not body.proxy_password and not body.proxy_private_key.strip():
        raise HTTPException(400, "Proxy password or proxy private key is required for jump host mode")
    if body.proxy_type == "socks5" and body.proxy_password and not body.proxy_username.strip():
        raise HTTPException(400, "Proxy username is required when SOCKS5 password is provided")


def _validate_exec_proxy(body: "AttackerSSHTargetBody") -> None:
    if body.exec_proxy_type not in {"none", "socks5"}:
        raise HTTPException(400, "Invalid exec_proxy_type")
    if body.exec_proxy_type == "none":
        return
    if not body.exec_proxy_host.strip():
        raise HTTPException(400, "Execution proxy host is required when exec_proxy_type is enabled")
    if body.exec_proxy_port <= 0 or body.exec_proxy_port > 65535:
        raise HTTPException(400, "Invalid execution proxy port")
    if body.exec_proxy_type == "socks5" and body.exec_proxy_password and not body.exec_proxy_username.strip():
        raise HTTPException(400, "Execution proxy username is required when execution proxy password is provided")
    if body.exec_jump_host.strip() and body.exec_jump_port <= 0:
        raise HTTPException(400, "Invalid execution jump port")


def _validate_attacker_target(body: "AttackerSSHTargetBody") -> None:
    _require_attacker_module_enabled()
    if not body.name.strip() or not body.host.strip() or not body.username.strip():
        raise HTTPException(400, "Name, host and username are required")
    if body.port <= 0 or body.port > 65535:
        raise HTTPException(400, "Invalid SSH port")
    _validate_main_proxy(body)
    _validate_exec_proxy(body)
    if not body.is_operator and not body.runs_pivot:
        raise HTTPException(400, "Target must be either an operator host, a pivot host, or both")


@router.get("/attacker-ssh/config", responses={400: {"description": "Bad request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}, 409: {"description": "Conflict"}})
def admin_get_attacker_ssh_config(admin: Annotated[models.User, Depends(require_admin)]):
    return {"targets": list_attacker_targets_safe()}


@router.post("/attacker-ssh/targets", status_code=201, responses={400: {"description": "Bad request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}, 409: {"description": "Conflict"}})
def admin_create_attacker_target(
    body: AttackerSSHTargetBody,
    admin: Annotated[models.User, Depends(require_admin)],
):
    _validate_attacker_target(body)
    if not body.password and not body.private_key.strip():
        raise HTTPException(400, "Password or private key is required")
    targets = list_attacker_targets()
    target = {
        "id": new_id("atk"),
        "name": body.name.strip(),
        "host": body.host.strip(),
        "port": body.port,
        "username": body.username.strip(),
        "password": body.password,
        "private_key": body.private_key,
        "known_hosts_policy": body.known_hosts_policy,
        "proxy_type": body.proxy_type,
        "proxy_host": body.proxy_host.strip(),
        "proxy_port": body.proxy_port,
        "proxy_username": body.proxy_username.strip(),
        "proxy_password": body.proxy_password,
        "proxy_private_key": body.proxy_private_key,
        "exec_proxy_type": body.exec_proxy_type,
        "exec_proxy_host": body.exec_proxy_host.strip(),
        "exec_proxy_port": body.exec_proxy_port,
        "exec_proxy_username": body.exec_proxy_username.strip(),
        "exec_proxy_password": body.exec_proxy_password,
        "exec_jump_host": body.exec_jump_host.strip(),
        "exec_jump_port": body.exec_jump_port,
        "exec_jump_username": body.exec_jump_username.strip(),
        "project_ids": body.project_ids,
        "enabled": body.enabled,
        "is_operator": body.is_operator,
        "runs_pivot": body.runs_pivot,
        "created_at": ts_now(),
    }
    targets.append(target)
    save_attacker_targets(targets)
    return next(item for item in list_attacker_targets_safe() if item.get("id") == target["id"])


def _resolve_next_credentials(body: "AttackerSSHTargetBody", target: dict) -> dict:
    return {
        "password": body.password if body.password else target.get("password", ""),
        "private_key": body.private_key if body.private_key.strip() else target.get("private_key", ""),
        "proxy_password": body.proxy_password if body.proxy_password else target.get("proxy_password", ""),
        "proxy_private_key": body.proxy_private_key if body.proxy_private_key.strip() else target.get("proxy_private_key", ""),
        "exec_proxy_password": body.exec_proxy_password if body.exec_proxy_password else target.get("exec_proxy_password", ""),
    }


@router.patch("/attacker-ssh/targets/{target_id}", responses={400: {"description": "Bad request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}, 409: {"description": "Conflict"}})
def admin_update_attacker_target(
    target_id: str,
    body: AttackerSSHTargetBody,
    admin: Annotated[models.User, Depends(require_admin)],
):
    _validate_attacker_target(body)
    targets = list_attacker_targets()
    for idx, target in enumerate(targets):
        if target.get("id") != target_id:
            continue
        creds = _resolve_next_credentials(body, target)
        next_password = creds["password"]
        next_private_key = creds["private_key"]
        next_proxy_password = creds["proxy_password"]
        next_proxy_private_key = creds["proxy_private_key"]
        next_exec_proxy_password = creds["exec_proxy_password"]
        if not next_password and not str(next_private_key).strip():
            raise HTTPException(400, "Password or private key is required")
        if (
            body.proxy_type == "jump"
            and not next_proxy_password
            and not str(next_proxy_private_key).strip()
        ):
            raise HTTPException(
                400, "Proxy password or proxy private key is required for jump host mode"
            )
        targets[idx] = {
            **target,
            "name": body.name.strip(),
            "host": body.host.strip(),
            "port": body.port,
            "username": body.username.strip(),
            "password": next_password,
            "private_key": next_private_key,
            "known_hosts_policy": body.known_hosts_policy,
            "proxy_type": body.proxy_type,
            "proxy_host": body.proxy_host.strip(),
            "proxy_port": body.proxy_port,
            "proxy_username": body.proxy_username.strip(),
            "proxy_password": next_proxy_password,
            "proxy_private_key": next_proxy_private_key,
            "exec_proxy_type": body.exec_proxy_type,
            "exec_proxy_host": body.exec_proxy_host.strip(),
            "exec_proxy_port": body.exec_proxy_port,
            "exec_proxy_username": body.exec_proxy_username.strip(),
            "exec_proxy_password": next_exec_proxy_password,
            "exec_jump_host": body.exec_jump_host.strip(),
            "exec_jump_port": body.exec_jump_port,
            "exec_jump_username": body.exec_jump_username.strip(),
            "project_ids": body.project_ids,
            "enabled": body.enabled,
            "is_operator": body.is_operator,
            "runs_pivot": body.runs_pivot,
        }
        save_attacker_targets(targets)
        return next(item for item in list_attacker_targets_safe() if item.get("id") == target_id)
    raise HTTPException(404, _MSG_ATTACKER_NOT_FOUND)


@router.delete("/attacker-ssh/targets/{target_id}", status_code=204, responses={400: {"description": "Bad request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}, 409: {"description": "Conflict"}})
def admin_delete_attacker_target(target_id: str, admin: Annotated[models.User, Depends(require_admin)]):
    targets = list_attacker_targets()
    filtered = [target for target in targets if target.get("id") != target_id]
    if len(filtered) == len(targets):
        raise HTTPException(404, _MSG_ATTACKER_NOT_FOUND)
    save_attacker_targets(filtered)


@router.post("/attacker-ssh/targets/{target_id}/test", responses={400: {"description": "Bad request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}, 409: {"description": "Conflict"}})
def admin_test_attacker_target(target_id: str, admin: Annotated[models.User, Depends(require_admin)]):
    _require_attacker_module_enabled()
    target = next((item for item in list_attacker_targets() if item.get("id") == target_id), None)
    if not target:
        raise HTTPException(404, _MSG_ATTACKER_NOT_FOUND)
    try:
        return run_ssh_command(target, "echo RootNotes SSH OK && whoami && hostname", 20)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/attacker-ssh/test", responses={400: {"description": "Bad request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}, 409: {"description": "Conflict"}})
def admin_test_attacker_ssh(
    body: AttackerSSHTargetBody,
    admin: Annotated[models.User, Depends(require_admin)],
):
    _validate_attacker_target(body)
    try:
        result = run_ssh_command(
            {
                "host": body.host.strip(),
                "port": body.port,
                "username": body.username.strip(),
                "password": body.password,
                "private_key": body.private_key,
                "known_hosts_policy": body.known_hosts_policy,
                "proxy_type": body.proxy_type,
                "proxy_host": body.proxy_host.strip(),
                "proxy_port": body.proxy_port,
                "proxy_username": body.proxy_username.strip(),
                "proxy_password": body.proxy_password,
                "proxy_private_key": body.proxy_private_key,
                "exec_proxy_type": body.exec_proxy_type,
                "exec_proxy_host": body.exec_proxy_host.strip(),
                "exec_proxy_port": body.exec_proxy_port,
                "exec_proxy_username": body.exec_proxy_username.strip(),
                "exec_proxy_password": body.exec_proxy_password,
                "exec_jump_host": body.exec_jump_host.strip(),
                "exec_jump_port": body.exec_jump_port,
                "exec_jump_username": body.exec_jump_username.strip(),
            },
            "echo RootNotes SSH OK && whoami && hostname",
            20,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    return result


@router.post("/attacker-ssh/execute", responses={400: {"description": "Bad request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}, 409: {"description": "Conflict"}})
def admin_execute_attacker_ssh(
    body: AttackerSSHExecuteBody,
    admin: Annotated[models.User, Depends(require_admin)],
):
    _require_attacker_module_enabled()
    targets = [target for target in list_attacker_targets() if target.get("enabled", True)]
    if not targets:
        raise HTTPException(400, "No global attacker targets are configured")
    try:
        return run_ssh_command(targets[0], body.command, body.timeout_seconds)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("", status_code=201, responses={400: {"description": "Bad request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}, 409: {"description": "Conflict"}})
def admin_create_module(body: CreateModuleBody, admin: Annotated[models.User, Depends(require_admin)]):
    try:
        return create_custom_module(
            body.name.strip(),
            body.title.strip(),
            body.version.strip(),
            body.description,
            body.enabled,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/upload", status_code=201, responses={400: {"description": "Bad request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}, 409: {"description": "Conflict"}})
async def admin_upload_module(
    admin: Annotated[models.User, Depends(require_admin)],
    file: Annotated[UploadFile, File()],
    x_plugin_signature: Annotated[str | None, Header(alias="X-Plugin-Signature")] = None,
):
    if not file.filename:
        raise HTTPException(400, "Missing filename")

    MODULES_DIR.mkdir(parents=True, exist_ok=True)
    content = await file.read()
    text = content.decode("utf-8", errors="ignore")

    if require_signature():
        if not x_plugin_signature:
            raise HTTPException(
                403,
                "PLUGIN_REQUIRE_SIGNATURE is enabled — upload must include X-Plugin-Signature header. "
                "Sign the module first via POST /api/admin/modules/sign.",
            )
        if not verify_signature(content, x_plugin_signature):
            raise HTTPException(
                403, "Invalid module signature — signature does not match file content"
            )

    module_name, warnings = _validate_module_source(file.filename, text)
    module_path = MODULES_DIR / f"{module_name}.py"
    if module_path.exists():
        raise HTTPException(409, "A module with this name already exists")

    module_path.write_bytes(content)
    try:
        module = load_plugin_module(module_name)
        payload = module.to_dict()
        payload["warnings"] = warnings
        payload["signed"] = bool(
            x_plugin_signature and verify_signature(content, x_plugin_signature)
        )
        return payload
    except Exception as e:
        module_path.unlink(missing_ok=True)
        raise HTTPException(400, f"Failed to load module: {e}\n\n{traceback.format_exc()}")


@router.patch("/{name}", responses={400: {"description": "Bad request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}, 409: {"description": "Conflict"}})
def admin_update_module(
    name: str,
    body: UpdateModuleBody,
    admin: Annotated[models.User, Depends(require_admin)],
):
    updated = update_module(
        name,
        enabled=body.enabled,
        title=body.title,
        version=body.version,
        description=body.description,
    )
    if not updated:
        raise HTTPException(404, "Module not found")
    return updated


@router.delete("/{name}", status_code=204, responses={400: {"description": "Bad request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}, 409: {"description": "Conflict"}})
def admin_delete_module(name: str, admin: Annotated[models.User, Depends(require_admin)]):
    if delete_custom_module(name) or delete_uploaded_module(name):
        return
    raise HTTPException(404, "Module not found or cannot be deleted")
