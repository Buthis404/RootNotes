from .types import BackendModule


class ModuleRegistry:
    def __init__(self):
        self._modules: dict[str, BackendModule] = {}

    def register(self, module: BackendModule):
        self._modules[module.name] = module

    def get_all(self) -> list[BackendModule]:
        return list(self._modules.values())

    def get_enabled(self) -> list[BackendModule]:
        return [m for m in self._modules.values() if m.enabled]

    def get(self, name: str) -> BackendModule | None:
        return self._modules.get(name)

    def get_scan_parser(self, format_name: str):
        """Find a scan parser across all enabled modules."""
        for module in self.get_enabled():
            if format_name in module.scan_parsers:
                return module.scan_parsers[format_name]
        return None

    def list_scan_parsers(self) -> list[str]:
        parsers = []
        for module in self.get_enabled():
            parsers.extend(module.scan_parsers.keys())
        return list(set(parsers))


# Global singleton
registry = ModuleRegistry()
