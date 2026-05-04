from dataclasses import dataclass, field
from typing import Callable, Any
from fastapi import APIRouter

from ..core.connectors import ToolConnector


@dataclass
class BackendModule:
    """Contract for a backend module/plugin."""
    name: str
    version: str
    title: str = ""
    description: str = ""
    enabled: bool = True
    source: str = "builtin"
    editable: bool = False
    router: APIRouter | None = None
    # Registries for extensible hooks
    scan_parsers: dict[str, Callable] = field(default_factory=dict)
    export_contributors: list[Callable] = field(default_factory=list)
    report_contributors: list[Callable] = field(default_factory=list)
    search_providers: list[Callable] = field(default_factory=list)
    startup_hooks: list[Callable] = field(default_factory=list)
    shutdown_hooks: list[Callable] = field(default_factory=list)
    connectors: list[ToolConnector] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "title": self.title or self.name,
            "version": self.version,
            "description": self.description,
            "enabled": self.enabled,
            "source": self.source,
            "editable": self.editable,
            "has_router": self.router is not None,
            "scan_parsers": list(self.scan_parsers.keys()),
            "connectors": [connector.to_dict() for connector in self.connectors],
        }
