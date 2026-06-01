import ipaddress
import re

from pydantic import BaseModel, model_validator

_HOSTNAME_RE = re.compile(r"^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


class ScopeBase(BaseModel):
    pid: str
    value: str
    scope_type: str = "cidr"
    in_scope: bool = True
    description: str = ""
    gateway_ip: str = ""
    is_entry: bool = False
    via_host_id: str = ""


class ScopeCreate(ScopeBase):
    @model_validator(mode="after")
    def validate_scope_value(self) -> "ScopeCreate":
        v = self.value.strip()
        if not v:
            raise ValueError("Scope value cannot be empty")
        st = self.scope_type
        if st in ("cidr", "ip"):
            try:
                ipaddress.ip_network(v, strict=False)
            except ValueError:
                try:
                    ipaddress.ip_address(v)
                except ValueError:
                    raise ValueError(f"Invalid CIDR or IP address: {v}")
        elif st == "domain" and not _HOSTNAME_RE.match(v):
            raise ValueError(f"Invalid domain or hostname: {v}")
        self.value = v
        return self


class ScopeUpdate(BaseModel):
    value: str | None = None
    scope_type: str | None = None
    in_scope: bool | None = None
    description: str | None = None
    gateway_ip: str | None = None
    is_entry: bool | None = None
    via_host_id: str | None = None


class Scope(ScopeBase):
    id: str
    model_config = {"from_attributes": True}
