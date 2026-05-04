from dataclasses import dataclass, field


@dataclass
class ToolConnector:
    """Normalized contract for orchestrated tools and integrations."""

    key: str
    title: str
    category: str
    description: str = ""
    supported_operations: list[str] = field(default_factory=list)
    supported_sources: list[str] = field(default_factory=list)
    creates_entities: list[str] = field(default_factory=list)
    execution_mode: str = "sync"  # sync | async | evented
    enabled: bool = True

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "title": self.title,
            "category": self.category,
            "description": self.description,
            "supported_operations": list(self.supported_operations),
            "supported_sources": list(self.supported_sources),
            "creates_entities": list(self.creates_entities),
            "execution_mode": self.execution_mode,
            "enabled": self.enabled,
        }
