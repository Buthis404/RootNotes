from dataclasses import dataclass, field
from typing import Callable, Any
from fastapi import APIRouter


@dataclass
class BackendModule:
    """Contract for a backend module/plugin."""
    name: str
    version: str
    description: str = ""
    enabled: bool = True
    router: APIRouter | None = None
    # Registries for extensible hooks
    scan_parsers: dict[str, Callable] = field(default_factory=dict)
    export_contributors: list[Callable] = field(default_factory=list)
    report_contributors: list[Callable] = field(default_factory=list)
    search_providers: list[Callable] = field(default_factory=list)
    startup_hooks: list[Callable] = field(default_factory=list)
    shutdown_hooks: list[Callable] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "enabled": self.enabled,
            "has_router": self.router is not None,
            "scan_parsers": list(self.scan_parsers.keys()),
        }
