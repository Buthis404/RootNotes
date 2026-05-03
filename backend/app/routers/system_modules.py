import ast
from pathlib import Path
import traceback
from datetime import datetime

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from .. import models
from ..core.deps import require_admin
from ..core.ssh_exec import run_ssh_command
from ..core.utils import new_id
from ..plugins.loader import load_plugin_module
from ..plugins.registry import registry
from ..plugins.state import list_modules, create_custom_module, update_module, delete_custom_module, delete_uploaded_module, MODULE_NAME_RE, list_attacker_targets, save_attacker_targets


router = APIRouter(prefix="/api/admin/modules", tags=["system-modules"])

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

FRONTEND_MODULE_TEMPLATE = '''import { moduleRegistry } from '../registry.js';

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
'''


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
    project_ids: list[str] = []
    enabled: bool = True


class AttackerSSHExecuteBody(BaseModel):
    command: str
    timeout_seconds: int = 30


def _require_attacker_module_enabled():
    module = registry.get("attacker_ssh")
    if not module or not module.enabled:
        raise HTTPException(404, "Attacker SSH module is disabled")


_DANGEROUS_IMPORTS = {"subprocess", "socket", "ctypes", "multiprocessing"}
_DANGEROUS_CALLS = {"eval", "exec", "__import__", "compile", "open"}


def _validate_module_source(filename: str, content: str) -> tuple[str, list[str]]:
    if not filename.endswith('.py'):
        raise HTTPException(400, 'Only .py module files are supported')

    module_name = Path(filename).stem
    if not MODULE_NAME_RE.match(module_name):
        raise HTTPException(400, 'Invalid module filename')
    if not content.strip():
        raise HTTPException(400, 'Uploaded module is empty')

    # Syntax check via AST
    try:
        tree = ast.parse(content, filename=filename)
    except SyntaxError as e:
        raise HTTPException(400, f"Syntax error in module (line {e.lineno}): {e.msg}")

    warnings = []

    # Scan AST for dangerous patterns
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
            for name in names:
                base = name.split(".")[0]
                if base in _DANGEROUS_IMPORTS:
                    warnings.append(f"Import of potentially sensitive module: {name!r}")
        elif isinstance(node, ast.Call):
            func = node.func
            call_name = ""
            if isinstance(func, ast.Name):
                call_name = func.id
            elif isinstance(func, ast.Attribute):
                call_name = f"{getattr(func.value, 'id', '')}.{func.attr}"
            if call_name in _DANGEROUS_CALLS or any(call_name.endswith(f".{d}") for d in _DANGEROUS_CALLS):
                warnings.append(f"Potentially dangerous call: {call_name!r}")

    if 'MODULE = BackendModule(' not in content:
        warnings.append('Template marker `MODULE = BackendModule(...)` was not found')
    if 'from ..types import BackendModule' not in content:
        warnings.append('Expected import `from ..types import BackendModule` was not found')
    return module_name, warnings


@router.get("")
def admin_list_modules(admin: models.User = Depends(require_admin)):
    return {"modules": list_modules()}


@router.get("/template")
def admin_module_template(admin: models.User = Depends(require_admin)):
    return PlainTextResponse(
        MODULE_TEMPLATE,
        headers={"Content-Disposition": 'attachment; filename="module_template.py"'},
        media_type="text/x-python",
    )


@router.get('/template/frontend')
def admin_frontend_module_template(admin: models.User = Depends(require_admin)):
    return PlainTextResponse(
        FRONTEND_MODULE_TEMPLATE,
        headers={'Content-Disposition': 'attachment; filename="frontend_module_template.js"'},
        media_type='application/javascript',
    )


@router.post('/validate')
def admin_validate_module(body: ValidateModuleBody, admin: models.User = Depends(require_admin)):
    module_name, warnings = _validate_module_source(body.filename, body.content)
    return {'ok': True, 'module_name': module_name, 'warnings': warnings}


def _validate_attacker_target(body: AttackerSSHTargetBody):
    _require_attacker_module_enabled()
    if not body.name.strip() or not body.host.strip() or not body.username.strip():
        raise HTTPException(400, "Name, host and username are required")
    if not body.password and not body.private_key.strip():
        raise HTTPException(400, "Password or private key is required")
    if body.port <= 0 or body.port > 65535:
        raise HTTPException(400, "Invalid SSH port")


@router.get("/attacker-ssh/config")
def admin_get_attacker_ssh_config(admin: models.User = Depends(require_admin)):
    return {"targets": list_attacker_targets()}


@router.post("/attacker-ssh/targets", status_code=201)
def admin_create_attacker_target(body: AttackerSSHTargetBody, admin: models.User = Depends(require_admin)):
    _validate_attacker_target(body)
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
        "project_ids": body.project_ids,
        "enabled": body.enabled,
        "created_at": datetime.utcnow().isoformat(),
    }
    targets.append(target)
    save_attacker_targets(targets)
    return target


@router.patch("/attacker-ssh/targets/{target_id}")
def admin_update_attacker_target(target_id: str, body: AttackerSSHTargetBody, admin: models.User = Depends(require_admin)):
    _validate_attacker_target(body)
    targets = list_attacker_targets()
    for idx, target in enumerate(targets):
        if target.get("id") != target_id:
            continue
        targets[idx] = {
            **target,
            "name": body.name.strip(),
            "host": body.host.strip(),
            "port": body.port,
            "username": body.username.strip(),
            "password": body.password,
            "private_key": body.private_key,
            "known_hosts_policy": body.known_hosts_policy,
            "project_ids": body.project_ids,
            "enabled": body.enabled,
        }
        save_attacker_targets(targets)
        return targets[idx]
    raise HTTPException(404, "Attacker target not found")


@router.delete("/attacker-ssh/targets/{target_id}", status_code=204)
def admin_delete_attacker_target(target_id: str, admin: models.User = Depends(require_admin)):
    targets = list_attacker_targets()
    filtered = [target for target in targets if target.get("id") != target_id]
    if len(filtered) == len(targets):
        raise HTTPException(404, "Attacker target not found")
    save_attacker_targets(filtered)


@router.post("/attacker-ssh/targets/{target_id}/test")
def admin_test_attacker_target(target_id: str, admin: models.User = Depends(require_admin)):
    _require_attacker_module_enabled()
    target = next((item for item in list_attacker_targets() if item.get("id") == target_id), None)
    if not target:
        raise HTTPException(404, "Attacker target not found")
    try:
        return run_ssh_command(target, "echo RootNotes SSH OK && whoami && hostname", 20)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/attacker-ssh/test")
def admin_test_attacker_ssh(body: AttackerSSHTargetBody, admin: models.User = Depends(require_admin)):
    _validate_attacker_target(body)
    try:
        result = run_ssh_command({
            "host": body.host.strip(),
            "port": body.port,
            "username": body.username.strip(),
            "password": body.password,
            "private_key": body.private_key,
            "known_hosts_policy": body.known_hosts_policy,
        }, "echo RootNotes SSH OK && whoami && hostname", 20)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return result


@router.post("/attacker-ssh/execute")
def admin_execute_attacker_ssh(body: AttackerSSHExecuteBody, admin: models.User = Depends(require_admin)):
    _require_attacker_module_enabled()
    targets = [target for target in list_attacker_targets() if target.get("enabled", True)]
    if not targets:
        raise HTTPException(400, "No global attacker targets are configured")
    try:
        return run_ssh_command(targets[0], body.command, body.timeout_seconds)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("", status_code=201)
def admin_create_module(body: CreateModuleBody, admin: models.User = Depends(require_admin)):
    try:
        return create_custom_module(body.name.strip(), body.title.strip(), body.version.strip(), body.description, body.enabled)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/upload", status_code=201)
async def admin_upload_module(file: UploadFile = File(...), admin: models.User = Depends(require_admin)):
    if not file.filename:
        raise HTTPException(400, 'Missing filename')

    MODULES_DIR.mkdir(parents=True, exist_ok=True)
    content = await file.read()
    module_name, warnings = _validate_module_source(file.filename, content.decode('utf-8', errors='ignore'))
    module_path = MODULES_DIR / f"{module_name}.py"
    if module_path.exists():
        raise HTTPException(409, "A module with this name already exists")

    module_path.write_bytes(content)
    try:
        module = load_plugin_module(module_name)
        payload = module.to_dict()
        payload['warnings'] = warnings
        return payload
    except Exception as e:
        module_path.unlink(missing_ok=True)
        raise HTTPException(400, f"Failed to load module: {e}\n\n{traceback.format_exc()}")


@router.patch("/{name}")
def admin_update_module(name: str, body: UpdateModuleBody, admin: models.User = Depends(require_admin)):
    updated = update_module(name, enabled=body.enabled, title=body.title, version=body.version, description=body.description)
    if not updated:
        raise HTTPException(404, "Module not found")
    return updated


@router.delete("/{name}", status_code=204)
def admin_delete_module(name: str, admin: models.User = Depends(require_admin)):
    if delete_custom_module(name) or delete_uploaded_module(name):
        return
    raise HTTPException(404, "Module not found or cannot be deleted")
