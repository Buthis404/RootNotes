"""Shared constants and validator mixins for all schema modules."""

from typing import Annotated

from pydantic import BaseModel, Field, field_validator

_TagItem = Annotated[str, Field(max_length=64)]
_Tags = Annotated[list[_TagItem], Field(max_length=100)]

_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_FINDING_STATUSES = {"open", "in_progress", "resolved", "accepted", "candidate", "confirmed"}
_HOST_STATUSES = {
    "unknown",
    "alive",
    "scanned",
    "access",
    "pwned",
    "owned",
    "up",
    "down",
    "unreachable",
    "attacker",
    "compromised",
}
_HOST_ROLES = {
    "unknown",
    "workstation",
    "server",
    "dc",
    "domain_controller",
    "router",
    "printer",
    "iot",
    "attacker",
    "pivot",
    "database",
    "firewall",
    "web",
    "mail",
    "other",
}
_CRED_TYPES = {"plain", "hash", "ntlm", "ticket", "key", "certificate", "token", "other"}


class _HostInputMixin(BaseModel):
    @field_validator("status", mode="before", check_fields=False)
    @classmethod
    def _val_host_status(cls, v):
        if v and v not in _HOST_STATUSES:
            raise ValueError(
                f"Invalid host status: {v!r}. Must be one of: {', '.join(sorted(_HOST_STATUSES))}"
            )
        return v

    @field_validator("role", mode="before", check_fields=False)
    @classmethod
    def _val_host_role(cls, v):
        if v and v not in _HOST_ROLES:
            raise ValueError(
                f"Invalid host role: {v!r}. Must be one of: {', '.join(sorted(_HOST_ROLES))}"
            )
        return v


class _CredInputMixin(BaseModel):
    @field_validator("type", mode="before", check_fields=False)
    @classmethod
    def _val_cred_type(cls, v):
        if v and v not in _CRED_TYPES:
            raise ValueError(
                f"Invalid credential type: {v!r}. Must be one of: {', '.join(sorted(_CRED_TYPES))}"
            )
        return v


class _FindingInputMixin(BaseModel):
    @field_validator("severity", mode="before", check_fields=False)
    @classmethod
    def _val_severity(cls, v):
        if v and v not in _SEVERITIES:
            raise ValueError(
                f"Invalid severity: {v!r}. Must be one of: {', '.join(sorted(_SEVERITIES))}"
            )
        return v

    @field_validator("status", mode="before", check_fields=False)
    @classmethod
    def _val_finding_status(cls, v):
        if v and v not in _FINDING_STATUSES:
            raise ValueError(
                f"Invalid finding status: {v!r}. Must be one of: {', '.join(sorted(_FINDING_STATUSES))}"
            )
        return v
