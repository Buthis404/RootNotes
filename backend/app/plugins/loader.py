"""
Module loader — registers built-in modules and discovers local plugin modules.

To add a new module:
  1. Create backend/app/plugins/modules/my_module.py
  2. Define MODULE = BackendModule(name="my_module", ...)
  3. The loader picks it up automatically on startup.
"""
import importlib
import pkgutil
from pathlib import Path

from .registry import registry
from .types import BackendModule


def _register_builtin_modules():
    """Register core built-in modules."""
    from fastapi import APIRouter

    # Topology module is registered separately via its router
    topology_module = BackendModule(
        name="topology",
        version="1.0.0",
        description="Automatic network topology builder from scan imports",
        enabled=True,
    )
    registry.register(topology_module)

    # Scan parsers module
    nmap_module = BackendModule(
        name="nmap_parser",
        version="1.0.0",
        description="Nmap XML topology parser",
        enabled=True,
        scan_parsers={"nmap": _nmap_parser_placeholder},
    )
    registry.register(nmap_module)


def _nmap_parser_placeholder(xml_content: str) -> list[dict]:
    """Placeholder — actual parsing done in topology router."""
    return []


def load_plugin_modules():
    """Discover and load plugin modules from plugins/modules/ directory."""
    modules_dir = Path(__file__).parent / "modules"
    if not modules_dir.exists():
        modules_dir.mkdir(exist_ok=True)
        return []

    loaded = []
    for finder, name, ispkg in pkgutil.iter_modules([str(modules_dir)]):
        try:
            mod = importlib.import_module(f".modules.{name}", package=__package__)
            if hasattr(mod, "MODULE") and isinstance(mod.MODULE, BackendModule):
                registry.register(mod.MODULE)
                loaded.append(mod.MODULE.name)
        except Exception as e:
            print(f"[plugins] Failed to load module {name}: {e}")

    return loaded


def initialize(app=None):
    """Call on startup to register all modules."""
    _register_builtin_modules()
    loaded = load_plugin_modules()
    if loaded:
        print(f"[plugins] Loaded modules: {', '.join(loaded)}")

    # Register module routers with the FastAPI app
    if app:
        for module in registry.get_enabled():
            if module.router:
                app.include_router(module.router)
